/**
 * @name postgresql-8e5793ab60bba65ffaa0f2237b39c9580d8972c7-ParallelSlotsSetup
 * @id cpp/postgresql/8e5793ab60bba65ffaa0f2237b39c9580d8972c7/ParallelSlotsSetup
 * @description postgresql-8e5793ab60bba65ffaa0f2237b39c9580d8972c7-src/bin/scripts/scripts_parallel.c-ParallelSlotsSetup CVE-2020-25694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vdbname_208, Parameter vhost_208, Parameter vport_208, Parameter vusername_209, Parameter vprompt_password_209, VariableAccess target_1) {
		target_1.getTarget()=vdbname_208
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectDatabase")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_208
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_208
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_209
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_209
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("bool")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(Literal).getValue()="1"
}

/*predicate func_2(Parameter vdbname_208, Parameter vhost_208, Parameter vport_208, Parameter vusername_209, Parameter vprompt_password_209, VariableAccess target_2) {
		target_2.getTarget()=vhost_208
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectDatabase")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdbname_208
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_208
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_209
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_209
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("bool")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(Literal).getValue()="1"
}

*/
/*predicate func_3(Parameter vdbname_208, Parameter vhost_208, Parameter vport_208, Parameter vusername_209, Parameter vprompt_password_209, VariableAccess target_3) {
		target_3.getTarget()=vport_208
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectDatabase")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdbname_208
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_208
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_209
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_209
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("bool")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(Literal).getValue()="1"
}

*/
/*predicate func_4(Parameter vdbname_208, Parameter vhost_208, Parameter vport_208, Parameter vusername_209, Parameter vprompt_password_209, VariableAccess target_4) {
		target_4.getTarget()=vusername_209
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectDatabase")
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdbname_208
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_208
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_208
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprompt_password_209
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("bool")
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(Literal).getValue()="1"
}

*/
/*predicate func_5(Parameter vdbname_208, Parameter vhost_208, Parameter vport_208, Parameter vusername_209, Parameter vprompt_password_209, VariableAccess target_5) {
		target_5.getTarget()=vprompt_password_209
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("connectDatabase")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdbname_208
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhost_208
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vport_208
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vusername_209
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("bool")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(Literal).getValue()="1"
}

*/
from Function func, Parameter vdbname_208, Parameter vhost_208, Parameter vport_208, Parameter vusername_209, Parameter vprompt_password_209, VariableAccess target_1
where
func_1(vdbname_208, vhost_208, vport_208, vusername_209, vprompt_password_209, target_1)
and vdbname_208.getType().hasName("const char *")
and vhost_208.getType().hasName("const char *")
and vport_208.getType().hasName("const char *")
and vusername_209.getType().hasName("const char *")
and vprompt_password_209.getType().hasName("bool")
and vdbname_208.getFunction() = func
and vhost_208.getFunction() = func
and vport_208.getFunction() = func
and vusername_209.getFunction() = func
and vprompt_password_209.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
