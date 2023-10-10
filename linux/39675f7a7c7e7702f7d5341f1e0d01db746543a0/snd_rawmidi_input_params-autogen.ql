/**
 * @name linux-39675f7a7c7e7702f7d5341f1e0d01db746543a0-snd_rawmidi_input_params
 * @id cpp/linux/39675f7a7c7e7702f7d5341f1e0d01db746543a0/snd_rawmidi_input_params
 * @description linux-39675f7a7c7e7702f7d5341f1e0d01db746543a0-snd_rawmidi_input_params 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vparams_666) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("krealloc")
		and not target_0.getTarget().hasName("kmalloc")
		and target_0.getArgument(0) instanceof PointerFieldAccess
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="buffer_size"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_666
		and target_0.getArgument(2).(BitwiseOrExpr).getValue()="6291648"
		and target_0.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="6291520"
		and target_0.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="6291456"
		and target_0.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="2097152"
		and target_0.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="4194304"
		and target_0.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_0.getArgument(2).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128")
}

predicate func_2(Parameter vparams_666, Variable vruntime_669) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("spin_lock_irq")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vruntime_669
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer_size"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_666
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer_size"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vruntime_669)
}

predicate func_3(Parameter vparams_666, Variable vruntime_669) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char *")
		and target_3.getExpr().(AssignExpr).getRValue() instanceof PointerFieldAccess
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer_size"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_666
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer_size"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vruntime_669)
}

predicate func_4(Parameter vparams_666, Variable vruntime_669) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="appl_ptr"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vruntime_669
		and target_4.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hw_ptr"
		and target_4.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vruntime_669
		and target_4.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer_size"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_666
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer_size"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vruntime_669)
}

predicate func_5(Parameter vparams_666, Variable vruntime_669) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("spin_unlock_irq")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vruntime_669
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer_size"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_666
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer_size"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vruntime_669)
}

predicate func_6(Parameter vparams_666, Variable vruntime_669) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer_size"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_666
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer_size"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vruntime_669)
}

predicate func_7(Variable vruntime_669) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="buffer"
		and target_7.getQualifier().(VariableAccess).getTarget()=vruntime_669
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall)
}

predicate func_9(Variable vruntime_669) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="buffer_size"
		and target_9.getQualifier().(VariableAccess).getTarget()=vruntime_669)
}

from Function func, Parameter vparams_666, Variable vruntime_669
where
func_0(vparams_666)
and not func_2(vparams_666, vruntime_669)
and not func_3(vparams_666, vruntime_669)
and not func_4(vparams_666, vruntime_669)
and not func_5(vparams_666, vruntime_669)
and not func_6(vparams_666, vruntime_669)
and func_7(vruntime_669)
and vparams_666.getType().hasName("snd_rawmidi_params *")
and vruntime_669.getType().hasName("snd_rawmidi_runtime *")
and func_9(vruntime_669)
and vparams_666.getParentScope+() = func
and vruntime_669.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
