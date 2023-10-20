/**
 * @name ghostscript-34cc326eb2c5695833361887fe0b32e8d987741c-do_execstack
 * @id cpp/ghostscript/34cc326eb2c5695833361887fe0b32e8d987741c/do-execstack
 * @description ghostscript-34cc326eb2c5695833361887fe0b32e8d987741c-psi/zcontrol.c-do_execstack CVE-2018-18073
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_3(Variable vrq_796, Parameter vi_ctx_p_790, ArrayExpr target_5, ExprStmt target_6, ValueFieldAccess target_7, ValueFieldAccess target_8) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("errorexec_find")
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_790
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrq_796
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrq_796
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getValue()="3584"
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(ArrayExpr target_5, Function func) {
	exists(BreakStmt target_4 |
		target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vrq_796, ArrayExpr target_5) {
		target_5.getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_5.getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_5.getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrq_796
		and target_5.getArrayOffset().(Literal).getValue()="1"
}

predicate func_6(Variable vrq_796, ExprStmt target_6) {
		target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="const_bytes"
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrq_796
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("const char *")
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrq_796
		and target_6.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(AddExpr).getValue()="4704"
		and target_6.getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="rsize"
		and target_6.getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_6.getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrq_796
		and target_6.getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strlen")
		and target_6.getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
}

predicate func_7(Parameter vi_ctx_p_790, ValueFieldAccess target_7) {
		target_7.getTarget().getName()="current"
		and target_7.getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_790
}

predicate func_8(Parameter vi_ctx_p_790, ValueFieldAccess target_8) {
		target_8.getTarget().getName()="stack"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_790
}

from Function func, Variable vrq_796, Parameter vi_ctx_p_790, ArrayExpr target_5, ExprStmt target_6, ValueFieldAccess target_7, ValueFieldAccess target_8
where
not func_3(vrq_796, vi_ctx_p_790, target_5, target_6, target_7, target_8)
and not func_4(target_5, func)
and func_5(vrq_796, target_5)
and func_6(vrq_796, target_6)
and func_7(vi_ctx_p_790, target_7)
and func_8(vi_ctx_p_790, target_8)
and vrq_796.getType().hasName("ref *")
and vi_ctx_p_790.getType().hasName("i_ctx_t *")
and vrq_796.(LocalVariable).getFunction() = func
and vi_ctx_p_790.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
