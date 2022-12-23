/**
 * @name linux-d3bd7413e0ca40b60cf60d4003246d067cafdeda-sanitize_ptr_alu
 * @id cpp/linux/d3bd7413e0ca40b60cf60d4003246d067cafdeda/sanitize_ptr_alu
 * @description linux-d3bd7413e0ca40b60cf60d4003246d067cafdeda-sanitize_ptr_alu 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter venv_3106, Parameter vinsn_3107) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("can_skip_alu_sanitation")
		and target_0.getArgument(0).(VariableAccess).getTarget()=venv_3106
		and target_0.getArgument(1).(VariableAccess).getTarget()=vinsn_3107)
}

predicate func_1(Variable vaux_3113, Variable valu_state_3116, Variable valu_limit_3116) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("update_alu_sanitation_state")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vaux_3113
		and target_1.getArgument(1).(VariableAccess).getTarget()=valu_state_3116
		and target_1.getArgument(2).(VariableAccess).getTarget()=valu_limit_3116)
}

predicate func_7(Parameter venv_3106, Parameter vinsn_3107) {
	exists(LogicalOrExpr target_7 |
		target_7.getAnOperand().(PointerFieldAccess).getTarget().getName()="allow_ptr_leaks"
		and target_7.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venv_3106
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="code"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinsn_3107
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_8(Variable vaux_3113, Variable valu_state_3116, Variable valu_limit_3116) {
	exists(LogicalAndExpr target_8 |
		target_8.getAnOperand().(PointerFieldAccess).getTarget().getName()="alu_state"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vaux_3113
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="alu_state"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vaux_3113
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=valu_state_3116
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="alu_limit"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vaux_3113
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=valu_limit_3116
		and target_8.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-13"
		and target_8.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="13")
}

predicate func_9(Variable vaux_3113, Variable valu_state_3116, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="alu_state"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vaux_3113
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=valu_state_3116
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

predicate func_10(Variable vaux_3113, Variable valu_limit_3116, Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="alu_limit"
		and target_10.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_10.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vaux_3113
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=valu_limit_3116
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

from Function func, Variable vaux_3113, Variable valu_state_3116, Variable valu_limit_3116, Parameter venv_3106, Parameter vinsn_3107
where
not func_0(venv_3106, vinsn_3107)
and not func_1(vaux_3113, valu_state_3116, valu_limit_3116)
and func_7(venv_3106, vinsn_3107)
and func_8(vaux_3113, valu_state_3116, valu_limit_3116)
and func_9(vaux_3113, valu_state_3116, func)
and func_10(vaux_3113, valu_limit_3116, func)
and vaux_3113.getType().hasName("bpf_insn_aux_data *")
and valu_state_3116.getType().hasName("u32")
and valu_limit_3116.getType().hasName("u32")
and venv_3106.getType().hasName("bpf_verifier_env *")
and vinsn_3107.getType().hasName("bpf_insn *")
and vaux_3113.getParentScope+() = func
and valu_state_3116.getParentScope+() = func
and valu_limit_3116.getParentScope+() = func
and venv_3106.getParentScope+() = func
and vinsn_3107.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
