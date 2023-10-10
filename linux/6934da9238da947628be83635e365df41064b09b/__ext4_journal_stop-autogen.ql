/**
 * @name linux-6934da9238da947628be83635e365df41064b09b-__ext4_journal_stop
 * @id cpp/linux/6934da9238da947628be83635e365df41064b09b/__ext4_journal_stop
 * @description linux-6934da9238da947628be83635e365df41064b09b-__ext4_journal_stop 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable verr_83) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=verr_83
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue() instanceof FunctionCall)
}

predicate func_4(Parameter vhandle_80) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("jbd2_journal_stop")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vhandle_80)
}

predicate func_5(Parameter vhandle_80) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="h_err"
		and target_5.getQualifier().(VariableAccess).getTarget()=vhandle_80)
}

predicate func_6(Parameter vhandle_80, Variable vrc_84, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_84
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jbd2_journal_stop")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhandle_80
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_9(Variable verr_83) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(VariableAccess).getTarget()=verr_83
		and target_9.getRValue() instanceof FunctionCall)
}

from Function func, Parameter vhandle_80, Variable verr_83, Variable vrc_84
where
func_0(verr_83)
and func_4(vhandle_80)
and func_5(vhandle_80)
and func_6(vhandle_80, vrc_84, func)
and vhandle_80.getType().hasName("handle_t *")
and verr_83.getType().hasName("int")
and func_9(verr_83)
and vrc_84.getType().hasName("int")
and vhandle_80.getParentScope+() = func
and verr_83.getParentScope+() = func
and vrc_84.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
