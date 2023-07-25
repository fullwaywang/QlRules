/**
 * @name libxml2-4472c3a5a5b516aaf59b89be602fbce52756c3e9-xmlParseEntityDecl
 * @id cpp/libxml2/4472c3a5a5b516aaf59b89be602fbce52756c3e9/xmlParseEntityDecl
 * @description libxml2-4472c3a5a5b516aaf59b89be602fbce52756c3e9-parser.c-xmlParseEntityDecl CVE-2016-4448
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="Space required after '%'\n"
		and not target_0.getValue()="Space required after '%%'\n"
		and target_0.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
