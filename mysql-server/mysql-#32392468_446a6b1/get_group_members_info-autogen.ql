/**
 * @name mysql-server-446a6b1a3fcd545f5e7ccdced48c344621036c18-get_group_members_info
 * @id cpp/mysql-server/446a6b1a3fcd545f5e7ccdced48c344621036c18/getgroupmembersinfo
 * @description mysql-server-446a6b1a3fcd545f5e7ccdced48c344621036c18-plugin/group_replication/src/ps_information.cc-get_group_members_info mysql-#32392468
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vgroup_member_manager_34, BlockStmt target_4, VariableAccess target_0) {
	exists(EQExpr obj_0 | obj_0=target_0.getParent() |
		obj_0.getRightOperand().(Literal).getValue()="0"
		and obj_0.getParent().(IfStmt).getThen()=target_4
	)
	and target_0.getTarget()=vgroup_member_manager_34
	and vgroup_member_manager_34.getIndex() = 2
}

predicate func_1(Parameter vgroup_member_manager_34, VariableAccess target_1) {
	target_1.getTarget()=vgroup_member_manager_34
	and vgroup_member_manager_34.getIndex() = 2
}

predicate func_2(Parameter vgroup_member_manager_34, VariableAccess target_2) {
	target_2.getTarget()=vgroup_member_manager_34
	and vgroup_member_manager_34.getIndex() = 2
}

predicate func_3(Parameter vgroup_member_manager_34, VariableAccess target_3) {
	target_3.getTarget()=vgroup_member_manager_34
	and vgroup_member_manager_34.getIndex() = 2
}

predicate func_4(Function func, BlockStmt target_4) {
	exists(ExprStmt obj_0 | obj_0=target_4.getStmt(1) |
		exists(VariableCall obj_1 | obj_1=obj_0.getExpr() |
			exists(ReferenceFieldAccess obj_2 | obj_2=obj_1.getExpr() |
				obj_2.getTarget().getName()="set_member_state"
				and obj_2.getQualifier().(VariableAccess).getTarget().getType().hasName("const GROUP_REPLICATION_GROUP_MEMBERS_CALLBACKS &")
			)
			and exists(ReferenceFieldAccess obj_3 | obj_3=obj_1.getArgument(0) |
				obj_3.getTarget().getName()="context"
				and obj_3.getQualifier().(VariableAccess).getTarget().getType().hasName("const GROUP_REPLICATION_GROUP_MEMBERS_CALLBACKS &")
			)
			and exists(FunctionCall obj_4 | obj_4=obj_1.getArgument(2) |
				obj_4.getTarget().hasName("strlen")
				and obj_4.getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
			)
			and obj_1.getArgument(1).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("const char *")
		)
	)
	and target_4.getEnclosingFunction() = func
}

from Function func, Parameter vgroup_member_manager_34, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, BlockStmt target_4
where
func_0(vgroup_member_manager_34, target_4, target_0)
and func_1(vgroup_member_manager_34, target_1)
and func_2(vgroup_member_manager_34, target_2)
and func_3(vgroup_member_manager_34, target_3)
and func_4(func, target_4)
and vgroup_member_manager_34.getType().hasName("Group_member_info_manager_interface *")
and vgroup_member_manager_34.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
