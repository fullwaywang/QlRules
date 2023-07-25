/**
 * @name ghostscript-37ed5022cecd584de868933b5b60da2e995b3179-s_xBCPE_process
 * @id cpp/ghostscript/37ed5022cecd584de868933b5b60da2e995b3179/s-xBCPE-process
 * @description ghostscript-37ed5022cecd584de868933b5b60da2e995b3179-base/sbcp.c-s_xBCPE_process CVE-2023-28879
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpw_40, Variable vp_42, Variable vq_45, LogicalAndExpr target_1, PointerArithmeticOperation target_2, ExprStmt target_3, PointerDereferenceExpr target_4, EqualityOperation target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="limit"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpw_40
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vq_45
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vp_42
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getOperand().(PrefixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PrefixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(LogicalAndExpr target_1) {
		target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("byte")
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="31"
		and target_1.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("const byte *")
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("byte")
}

predicate func_2(Parameter vpw_40, Variable vq_45, PointerArithmeticOperation target_2) {
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="limit"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpw_40
		and target_2.getRightOperand().(VariableAccess).getTarget()=vq_45
}

predicate func_3(Parameter vpw_40, Variable vq_45, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ptr"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpw_40
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vq_45
}

predicate func_4(Variable vp_42, PointerDereferenceExpr target_4) {
		target_4.getOperand().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_42
}

predicate func_5(Variable vp_42, EqualityOperation target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=vp_42
		and target_5.getAnOperand().(VariableAccess).getTarget().getType().hasName("const byte *")
}

predicate func_6(Variable vq_45, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vq_45
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Parameter vpw_40, Variable vp_42, Variable vq_45, LogicalAndExpr target_1, PointerArithmeticOperation target_2, ExprStmt target_3, PointerDereferenceExpr target_4, EqualityOperation target_5, ExprStmt target_6
where
not func_0(vpw_40, vp_42, vq_45, target_1, target_2, target_3, target_4, target_5, target_6)
and func_1(target_1)
and func_2(vpw_40, vq_45, target_2)
and func_3(vpw_40, vq_45, target_3)
and func_4(vp_42, target_4)
and func_5(vp_42, target_5)
and func_6(vq_45, target_6)
and vpw_40.getType().hasName("stream_cursor_write *")
and vp_42.getType().hasName("const byte *")
and vq_45.getType().hasName("byte *")
and vpw_40.getFunction() = func
and vp_42.(LocalVariable).getFunction() = func
and vq_45.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
