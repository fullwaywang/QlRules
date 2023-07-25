/**
 * @name imagemagick-68154c05cf40a80b6f2e2dd9fdc4428570f875f0-ReadPDFImage
 * @id cpp/imagemagick/68154c05cf40a80b6f2e2dd9fdc4428570f875f0/ReadPDFImage
 * @description imagemagick-68154c05cf40a80b6f2e2dd9fdc4428570f875f0-coders/pdf.c-ReadPDFImage CVE-2020-29599
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="&;<>|\""
		and not target_0.getValue()="&;<>|\"'"
		and target_0.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
