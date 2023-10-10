/**
 * @name libxml2-cbb271655cadeb8dbb258a64701d9a3a0c4835b4-xmlFAParseCharRange
 * @id cpp/libxml2/cbb271655cadeb8dbb258a64701d9a3a0c4835b4/xmlFAParseCharRange
 * @description libxml2-cbb271655cadeb8dbb258a64701d9a3a0c4835b4-xmlFAParseCharRange CVE-2016-1840
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_4987, Variable vlen_4988, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cur"
		and target_0.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4987
		and target_0.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vlen_4988
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Function func) {
	exists(EmptyStmt target_1 |
		target_1.toString() = ";"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Parameter vctxt_4987, Variable vlen_4988
where
func_0(vctxt_4987, vlen_4988, func)
and func_1(func)
and vctxt_4987.getType().hasName("xmlRegParserCtxtPtr")
and vlen_4988.getType().hasName("int")
and vctxt_4987.getParentScope+() = func
and vlen_4988.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
