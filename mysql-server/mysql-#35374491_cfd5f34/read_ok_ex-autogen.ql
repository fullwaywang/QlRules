/**
 * @name mysql-server-cfd5f342dfdbb5de1cffc9f28851623df80ea357-read_ok_ex
 * @id cpp/mysql-server/cfd5f342dfdbb5de1cffc9f28851623df80ea357/readokex
 * @description mysql-server-cfd5f342dfdbb5de1cffc9f28851623df80ea357-sql-common/client.c-read_ok_ex mysql-#35374491
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlength_741, Variable vlen_742, Variable vpos_743, Parameter vmysql_741, VariableAccess target_1, ExprStmt target_2, LogicalAndExpr target_3, ExprStmt target_4, AddressOfExpr target_5) {
exists(IfStmt target_0 |
	exists(NotExpr obj_0 | obj_0=target_0.getCondition() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getOperand() |
			obj_1.getTarget().hasName("buffer_check_remaining")
			and obj_1.getArgument(0).(VariableAccess).getTarget()=vmysql_741
			and obj_1.getArgument(1).(VariableAccess).getTarget()=vpos_743
			and obj_1.getArgument(2).(VariableAccess).getTarget()=vlength_741
			and obj_1.getArgument(3).(VariableAccess).getTarget()=vlen_742
		)
	)
	and exists(NotExpr obj_2 | obj_2=target_0.getCondition() |
		exists(FunctionCall obj_3 | obj_3=obj_2.getOperand() |
			obj_3.getArgument(2).(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
			and obj_3.getArgument(3).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation())
		)
	)
	and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_1
	and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
	and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
)
}

predicate func_1(Variable vtype_752, VariableAccess target_1) {
	target_1.getTarget()=vtype_752
}

predicate func_2(Parameter vlength_741, Variable vlen_742, Variable vpos_743, Parameter vmysql_741, VariableAccess target_1, ExprStmt target_2) {
	exists(AssignExpr obj_0 | obj_0=target_2.getExpr() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getRValue() |
			obj_1.getTarget().hasName("net_field_length_ll_safe")
			and obj_1.getArgument(0).(VariableAccess).getTarget()=vmysql_741
			and obj_1.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpos_743
			and obj_1.getArgument(2).(VariableAccess).getTarget()=vlength_741
			and obj_1.getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("my_bool")
		)
		and obj_0.getLValue().(VariableAccess).getTarget()=vlen_742
	)
	and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_1
}

predicate func_3(Parameter vlength_741, Variable vpos_743, Parameter vmysql_741, LogicalAndExpr target_3) {
	exists(RelationalOperation obj_0 | obj_0=target_3.getLeftOperand() |
		exists(PointerArithmeticOperation obj_1 | obj_1=obj_0.getGreaterOperand() |
			exists(ValueFieldAccess obj_2 | obj_2=obj_1.getLeftOperand() |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getQualifier() |
					obj_3.getTarget().getName()="net"
					and obj_3.getQualifier().(VariableAccess).getTarget()=vmysql_741
				)
				and obj_2.getTarget().getName()="read_pos"
			)
			and obj_1.getRightOperand().(VariableAccess).getTarget()=vlength_741
		)
		and obj_0.getLesserOperand().(VariableAccess).getTarget()=vpos_743
	)
	and exists(FunctionCall obj_4 | obj_4=target_3.getRightOperand() |
		obj_4.getTarget().hasName("net_field_length")
		and obj_4.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpos_743
	)
}

predicate func_4(Variable vlen_742, Variable vpos_743, VariableAccess target_1, ExprStmt target_4) {
	exists(AssignPointerAddExpr obj_0 | obj_0=target_4.getExpr() |
		obj_0.getLValue().(VariableAccess).getTarget()=vpos_743
		and obj_0.getRValue().(VariableAccess).getTarget()=vlen_742
	)
	and target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_1
}

predicate func_5(Parameter vlength_741, Variable vpos_743, Parameter vmysql_741, AddressOfExpr target_5) {
	exists(FunctionCall obj_0 | obj_0=target_5.getParent() |
		exists(AssignExpr obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getRValue() |
				obj_2.getTarget().hasName("net_field_length_ll_safe")
				and obj_2.getArgument(0).(VariableAccess).getTarget()=vmysql_741
				and obj_2.getArgument(2).(VariableAccess).getTarget()=vlength_741
				and obj_2.getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("my_bool")
			)
		)
	)
	and target_5.getOperand().(VariableAccess).getTarget()=vpos_743
}

from Function func, Parameter vlength_741, Variable vlen_742, Variable vpos_743, Variable vtype_752, Parameter vmysql_741, VariableAccess target_1, ExprStmt target_2, LogicalAndExpr target_3, ExprStmt target_4, AddressOfExpr target_5
where
not func_0(vlength_741, vlen_742, vpos_743, vmysql_741, target_1, target_2, target_3, target_4, target_5)
and func_1(vtype_752, target_1)
and func_2(vlength_741, vlen_742, vpos_743, vmysql_741, target_1, target_2)
and func_3(vlength_741, vpos_743, vmysql_741, target_3)
and func_4(vlen_742, vpos_743, target_1, target_4)
and func_5(vlength_741, vpos_743, vmysql_741, target_5)
and vlength_741.getType().hasName("ulong")
and vlen_742.getType().hasName("size_t")
and vpos_743.getType().hasName("uchar *")
and vtype_752.getType().hasName("enum_session_state_type")
and vmysql_741.getType().hasName("MYSQL *")
and vlength_741.getFunction() = func
and vlen_742.(LocalVariable).getFunction() = func
and vpos_743.(LocalVariable).getFunction() = func
and vtype_752.(LocalVariable).getFunction() = func
and vmysql_741.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
