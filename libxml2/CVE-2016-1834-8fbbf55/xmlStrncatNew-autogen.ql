/**
 * @name libxml2-8fbbf5513d609c1770b391b99e33314cd0742704-xmlStrncatNew
 * @id cpp/libxml2/8fbbf5513d609c1770b391b99e33314cd0742704/xmlStrncatNew
 * @description libxml2-8fbbf5513d609c1770b391b99e33314cd0742704-xmlstring.c-xmlStrncatNew CVE-2016-1834
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_483, RelationalOperation target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_483
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3)
}

predicate func_1(Variable vsize_484, ExprStmt target_4, MulExpr target_5, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_484
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_1)
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getLeftOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vstr2_483, Parameter vlen_483, RelationalOperation target_3, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_483
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrlen")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstr2_483
		and target_2.getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Parameter vlen_483, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vlen_483
		and target_3.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_4(Variable vsize_484, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_484
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrlen")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const xmlChar *")
}

predicate func_5(Parameter vlen_483, Variable vsize_484, MulExpr target_5) {
		target_5.getLeftOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_484
		and target_5.getLeftOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_483
		and target_5.getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_5.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_5.getRightOperand().(SizeofTypeOperator).getValue()="1"
}

from Function func, Parameter vstr2_483, Parameter vlen_483, Variable vsize_484, ExprStmt target_2, RelationalOperation target_3, ExprStmt target_4, MulExpr target_5
where
not func_0(vlen_483, target_3)
and not func_1(vsize_484, target_4, target_5, func)
and func_2(vstr2_483, vlen_483, target_3, target_2)
and func_3(vlen_483, target_3)
and func_4(vsize_484, target_4)
and func_5(vlen_483, vsize_484, target_5)
and vstr2_483.getType().hasName("const xmlChar *")
and vlen_483.getType().hasName("int")
and vsize_484.getType().hasName("int")
and vstr2_483.getFunction() = func
and vlen_483.getFunction() = func
and vsize_484.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
