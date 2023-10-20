/**
 * @name json-c-d07b91014986900a3a75f306d302e13e005e9d67-printbuf_extend
 * @id cpp/json-c/d07b91014986900a3a75f306d302e13e005e9d67/printbuf-extend
 * @description json-c-d07b91014986900a3a75f306d302e13e005e9d67-printbuf.c-printbuf_extend CVE-2020-12762
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmin_size_61, RelationalOperation target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmin_size_61
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="2147483639"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_4.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_61, Parameter vmin_size_61, Variable vnew_size_64, RelationalOperation target_4, ExprStmt target_2, RelationalOperation target_5, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_61
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="1073741823"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_size_64
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vmin_size_61
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="8"
		and target_1.getElse().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getElse().(BlockStmt).getStmt(1) instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1)
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vp_61, Variable vnew_size_64, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_size_64
		and target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_61
		and target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vmin_size_61, Variable vnew_size_64, Function func, IfStmt target_3) {
		target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnew_size_64
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vmin_size_61
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="8"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_size_64
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vmin_size_61
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="8"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Parameter vp_61, Parameter vmin_size_61, RelationalOperation target_4) {
		 (target_4 instanceof GEExpr or target_4 instanceof LEExpr)
		and target_4.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_61
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vmin_size_61
}

predicate func_5(Parameter vmin_size_61, Variable vnew_size_64, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vnew_size_64
		and target_5.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vmin_size_61
		and target_5.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="8"
}

from Function func, Parameter vp_61, Parameter vmin_size_61, Variable vnew_size_64, ExprStmt target_2, IfStmt target_3, RelationalOperation target_4, RelationalOperation target_5
where
not func_0(vmin_size_61, target_4, func)
and not func_1(vp_61, vmin_size_61, vnew_size_64, target_4, target_2, target_5, func)
and func_2(vp_61, vnew_size_64, func, target_2)
and func_3(vmin_size_61, vnew_size_64, func, target_3)
and func_4(vp_61, vmin_size_61, target_4)
and func_5(vmin_size_61, vnew_size_64, target_5)
and vp_61.getType().hasName("printbuf *")
and vmin_size_61.getType().hasName("int")
and vnew_size_64.getType().hasName("int")
and vp_61.getParentScope+() = func
and vmin_size_61.getParentScope+() = func
and vnew_size_64.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
