/**
 * @name libxml2-8fbbf5513d609c1770b391b99e33314cd0742704-xmlStrncatNew
 * @id cpp/libxml2/8fbbf5513d609c1770b391b99e33314cd0742704/xmlStrncatNew
 * @description libxml2-8fbbf5513d609c1770b391b99e33314cd0742704-xmlStrncatNew CVE-2016-1834
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_483) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_483
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_483
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_1(Variable vsize_484, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_484
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vstr2_483, Parameter vlen_483) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_483
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrlen")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstr2_483
		and target_2.getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_483
		and target_2.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_3(Parameter vlen_483) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vlen_483
		and target_3.getGreaterOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen() instanceof ExprStmt)
}

predicate func_4(Parameter vstr1_483, Variable vsize_484) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vsize_484
		and target_4.getRValue().(FunctionCall).getTarget().hasName("xmlStrlen")
		and target_4.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstr1_483)
}

from Function func, Parameter vstr1_483, Parameter vstr2_483, Parameter vlen_483, Variable vsize_484
where
not func_0(vlen_483)
and not func_1(vsize_484, func)
and func_2(vstr2_483, vlen_483)
and vstr2_483.getType().hasName("const xmlChar *")
and vlen_483.getType().hasName("int")
and func_3(vlen_483)
and vsize_484.getType().hasName("int")
and func_4(vstr1_483, vsize_484)
and vstr1_483.getParentScope+() = func
and vstr2_483.getParentScope+() = func
and vlen_483.getParentScope+() = func
and vsize_484.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
