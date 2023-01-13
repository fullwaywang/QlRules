/**
 * @name libxml2-7ffcd44d7e6c46704f8af0321d9314cd26e0e18a-xmlSchemaPreRun
 * @id cpp/libxml2/7ffcd44d7e6c46704f8af0321d9314cd26e0e18a/xmlSchemaPreRun
 * @description libxml2-7ffcd44d7e6c46704f8af0321d9314cd26e0e18a-xmlSchemaPreRun CVE-2019-20388
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvctxt_28085) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="xsiAssemble"
		and target_0.getQualifier().(VariableAccess).getTarget()=vvctxt_28085
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue() instanceof PointerFieldAccess
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Parameter vvctxt_28085
where
func_0(vvctxt_28085)
and func_1(func)
and vvctxt_28085.getType().hasName("xmlSchemaValidCtxtPtr")
and vvctxt_28085.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
