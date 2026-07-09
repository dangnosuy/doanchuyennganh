"""
context_manager.py — Quản lý ngữ cảnh hội thoại cho pipeline MARL.

Cung cấp lớp ContextManager để nén hội thoại dài, lưu vào MemoryStore,
và xây dựng chuỗi ngữ cảnh phù hợp cho từng agent trước khi gọi LLM.
"""

from openai import OpenAI

from shared.utils import truncate


class ContextManager:
    """Nén hội thoại và cung cấp ngữ cảnh liên quan cho các agent."""

    _compress_count: int = 0

    def __init__(self, memory_store, llm_client: OpenAI, model: str):
        """
        Args:
            memory_store: Instance của MemoryStore.
            llm_client:   OpenAI client đã được khởi tạo.
            model:        Tên model dùng để tóm tắt.
        """
        self.memory_store = memory_store
        self.llm_client = llm_client
        self.model = model

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compress_if_needed(
        self,
        conversation: list[dict],
        trigger_len: int = 20,
        keep_recent: int = 6,
    ) -> list[dict]:
        """Nén hội thoại nếu vượt quá trigger_len tin nhắn.

        Nếu len(conversation) > trigger_len:
          1. Lấy conversation[:-keep_recent] → gọi LLM tóm tắt.
          2. Giữ nguyên conversation[-keep_recent:].
          3. Thay thế các tin nhắn cũ bằng một SYSTEM message chứa tóm tắt.
          4. Lưu toàn bộ tin nhắn cũ vào memory_store.
          5. Cập nhật memory_store summary.
        Trả về conversation đã được sửa đổi (in-place).
        """
        if len(conversation) <= trigger_len:
            return conversation

        split_point = len(conversation) - keep_recent
        old_messages = conversation[:split_point]
        recent_messages = conversation[split_point:]

        # Tóm tắt các tin nhắn cũ
        summary = self._summarize(old_messages)

        # KHÔNG log lại từng message cũ ở đây — ManageAgent đã log realtime
        # mỗi tick rồi. Chỉ cập nhật rolling summary để RAG có thể dùng.

        # Cập nhật summary trong memory_store
        self.memory_store.update_summary(summary)

        # Xây dựng SYSTEM message thay thế
        n = len(old_messages)
        compressed_content = (
            f"[CONTEXT SUMMARY — {n} tin nhắn đã được nén]\n{summary}"
        )
        compressed_msg = {
            "speaker": "SYSTEM",
            "content": compressed_content,
        }

        # Thay thế in-place: xóa hết rồi thêm lại
        conversation.clear()
        conversation.append(compressed_msg)
        conversation.extend(recent_messages)

        ContextManager._compress_count += 1

        return conversation

    def get_context_for_agent(
        self,
        agent_id: str,
        conversation: list[dict],
        keywords: list[str] = None,
    ) -> str:
        """Xây dựng chuỗi ngữ cảnh cho agent trước khi được gọi.

        Kết hợp:
          - Tóm tắt hội thoại hiện tại (nếu có).
          - Bộ nhớ liên quan từ memory_store (nếu có keywords).
          - Ghi chú về số lần nén đã thực hiện.

        Trả về chuỗi rỗng nếu không có tóm tắt lẫn bộ nhớ liên quan
        (tránh inject nhiễu).
        """
        parts: list[str] = []

        # Lấy tóm tắt tổng thể
        summary = self.memory_store.get_summary()
        if summary and summary.strip():
            parts.append(f"### Tóm tắt phiên làm việc\n{summary.strip()}")

        # Lấy bộ nhớ liên quan theo từ khoá
        if keywords:
            relevant = self.memory_store.get_relevant_context(
                agent=agent_id,
                keywords=keywords,
                max_chars=1200,
            )
            if relevant and relevant.strip():
                parts.append(
                    f"### Ngữ cảnh liên quan (dành cho {agent_id})\n{relevant.strip()}"
                )

        if not parts:
            return ""

        # Thêm ghi chú số lần nén
        if ContextManager._compress_count > 0:
            parts.append(
                f"_(Hội thoại đã được nén {ContextManager._compress_count} lần — "
                "các tin nhắn cũ được lưu trong bộ nhớ.)_"
            )

        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _summarize(self, messages: list[dict]) -> str:
        """Gọi LLM để tóm tắt danh sách tin nhắn hội thoại.

        System prompt yêu cầu trích xuất:
          - Các chiến lược tấn công đã đề xuất.
          - Những gì bị từ chối và lý do.
          - Endpoint/thông tin xác thực đã phát hiện.
          - Trạng thái kế hoạch tấn công hiện tại.

        Trả về tóm tắt bằng tiếng Việt, tối đa 800 từ.
        """
        system_prompt = (
            "Bạn là trợ lý tóm tắt phiên làm việc kiểm thử thâm nhập (pentest).\n"
            "Hãy đọc đoạn hội thoại dưới đây giữa các agent (REDTEAM, BLUETEAM, AGENT, SYSTEM, USER) "
            "và tóm tắt lại những thông tin quan trọng nhất bằng tiếng Việt, tối đa 800 từ.\n\n"
            "Cần trích xuất và trình bày rõ:\n"
            "1. Các chiến lược tấn công đã được đề xuất (tên, mô tả ngắn).\n"
            "2. Những chiến lược hoặc bước nào bị từ chối, và lý do cụ thể.\n"
            "3. Các endpoint, thông tin xác thực, token, cookie hoặc lỗ hổng đã phát hiện.\n"
            "4. Trạng thái hiện tại của kế hoạch tấn công (đang ở bước nào, kết quả ra sao).\n"
            "5. Bất kỳ kết luận hoặc bằng chứng quan trọng nào từ ExecAgent.\n\n"
            "Chỉ trả về nội dung tóm tắt, không thêm lời giải thích hay tiêu đề thừa."
        )

        # Chuyển danh sách tin nhắn thành văn bản hội thoại
        conversation_text_parts: list[str] = []
        for msg in messages:
            speaker = msg.get("speaker", "UNKNOWN")
            content = msg.get("content", "")
            conversation_text_parts.append(f"[{speaker}]: {content}")

        raw_conversation = "\n\n".join(conversation_text_parts)
        # Giới hạn độ dài đầu vào để tránh vượt context window
        user_content = truncate(raw_conversation, limit=12000)

        try:
            response = self.llm_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                temperature=0.1,
                max_tokens=1024,
            )
            summary = response.choices[0].message.content or ""
            return summary.strip()
        except Exception as exc:  # noqa: BLE001
            # Không để lỗi LLM làm hỏng pipeline chính
            return f"(Không thể tóm tắt tự động: {exc})"
