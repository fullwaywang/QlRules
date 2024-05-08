/**
 * @name mysql-server-446a6b1a3fcd545f5e7ccdced48c344621036c18-get_group_member_stats
 * @id cpp/mysql-server/446a6b1a3fcd545f5e7ccdced48c344621036c18/getgroupmemberstats
 * @description mysql-server-446a6b1a3fcd545f5e7ccdced48c344621036c18-plugin/group_replication/src/ps_information.cc-get_group_member_stats mysql-#32392468
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vgroup_member_manager_142, BlockStmt target_3, VariableAccess target_0) {
	exists(EQExpr obj_0 | obj_0=target_0.getParent() |
		obj_0.getRightOperand().(Literal).getValue()="0"
		and obj_0.getParent().(IfStmt).getThen()=target_3
	)
	and target_0.getTarget()=vgroup_member_manager_142
	and vgroup_member_manager_142.getIndex() = 2
}

predicate func_1(Parameter vgroup_member_manager_142, VariableAccess target_1) {
	target_1.getTarget()=vgroup_member_manager_142
	and vgroup_member_manager_142.getIndex() = 2
}

predicate func_2(Parameter vgroup_member_manager_142, VariableAccess target_2) {
	target_2.getTarget()=vgroup_member_manager_142
	and vgroup_member_manager_142.getIndex() = 2
}

predicate func_3(Function func, BlockStmt target_3) {
	target_3.getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
	and target_3.getEnclosingFunction() = func
}

from Function func, Parameter vgroup_member_manager_142, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, BlockStmt target_3
where
func_0(vgroup_member_manager_142, target_3, target_0)
and func_1(vgroup_member_manager_142, target_1)
and func_2(vgroup_member_manager_142, target_2)
and func_3(func, target_3)
and vgroup_member_manager_142.getType().hasName("Group_member_info_manager_interface *")
and vgroup_member_manager_142.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
