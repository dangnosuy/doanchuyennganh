\NeedsTeXFormat{LaTeX2e}

\providecommand{\baseclass}{book}
\newcommand{\classname}{thesis}
\ProvidesClass{\classname}[2023/12/23 v1.0 Thesis]

\DeclareOption*{\PassOptionsToClass{\CurrentOption}{\baseclass}}
\ProcessOptions\relax
\LoadClass{\baseclass}


%=========================== Typography ==========================%
\usepackage[charter]{mathdesign}
\RequirePackage[utf8]{vietnam}
\RequirePackage[utf8]{inputenc}

\linespread{1.2}

%============================= Images ============================%
\RequirePackage{graphicx}
\RequirePackage{subcaption}


%============================= Tables ============================%
\RequirePackage{threeparttable}
\RequirePackage{makecell}
\RequirePackage{multirow}
\RequirePackage{longtable}
\RequirePackage{booktabs}


%============================ Drawing ============================%
\RequirePackage{tikz}
\usetikzlibrary{calc} 


%========================= Page & Layout ==========================%
\RequirePackage{geometry}
\usepackage{pdfpages}
\geometry{
    paper=a4paper,
    bindingoffset=.5cm,
    left=3.0cm,
    right=3.0cm,
    bottom=3.5cm,
    bmargin=3.0cm,
    tmargin=3.0cm,
    headheight=16pt,
}


\RequirePackage{fancyhdr}


%============================ Colors =============================%
\RequirePackage{xcolor}
\definecolor{blue}{HTML}{3F63B1}


%======================= Maths & Algorithms =======================%
\RequirePackage{amsmath}

\RequirePackage{algorithm}
\RequirePackage[linesnumbered,ruled,vlined,algo2e]{algorithm2e}

\SetKwInput{KwInput}{Input}
\SetKwInput{KwOutput}{Output}
\SetKwInput{KwInit}{Init}
\SetKwProg{Fn}{Function}{:}{end}

%==================== Cites, Links & References ===================%
\RequirePackage[backend=biber,style=numeric]{biblatex}
\addbibresource{references.bib}

\RequirePackage[hidelinks, unicode]{hyperref}


%======================= Headings & captions ======================%
\renewcommand{\chaptername}{Chương}

\RequirePackage{titlesec}
\titleformat{\chapter}[display]
  {\normalfont\huge\bfseries\centering}{\chaptertitlename\ \thechapter}{20pt}{\Huge}

\RequirePackage[labelfont=bf]{caption}


%============================ Others =============================%
\RequirePackage{float}
\RequirePackage{adjustbox}


\newcommand{\abbrevname}{DANH MỤC TỪ VIẾT TẮT}
\NewDocumentEnvironment{abbreviations}{ m }{%
	\begin{longtable}{#1}
	}{%
	\end{longtable}
	\addtocounter{table}{-1}% Don't count this table as one of the document tables
}

\newcommand{\transname}{DANH MỤC TỪ TẠM DỊCH}
\NewDocumentEnvironment{translatetion}{ m }{%
	\begin{longtable}{#1}
	}{%
	\end{longtable}
	\addtocounter{table}{-1}% Don't count this table as one of the document tables
}
