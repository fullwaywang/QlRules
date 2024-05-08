/**
 * @name mysql-server-c08374fb474c633b49177fe45923a344355f384b-dispatch_command
 * @id cpp/mysql-server/c08374fb474c633b49177fe45923a344355f384b/dispatchcommand
 * @description mysql-server-c08374fb474c633b49177fe45923a344355f384b-sql/sql_parse.cc-dispatch_command mysql-#33206343
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vthd_1580, ExprStmt target_1, FunctionCall target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getArgument(1) |
		exists(FunctionCall obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().hasName("get_protocol_classic")
			and obj_1.getQualifier().(VariableAccess).getTarget()=vthd_1580
		)
		and obj_0.getTarget().hasName("get_raw_packet")
	)
	and exists(FunctionCall obj_2 | obj_2=target_0.getArgument(2) |
		exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
			obj_3.getTarget().hasName("get_protocol_classic")
			and obj_3.getQualifier().(VariableAccess).getTarget()=vthd_1580
		)
		and obj_2.getTarget().hasName("get_packet_length")
	)
	and target_0.getTarget().hasName("register_slave")
	and not target_0.getTarget().hasName("register_replica")
	and target_0.getArgument(0).(VariableAccess).getTarget()=vthd_1580
	and target_0.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_1
}

predicate func_1(Parameter vthd_1580, NotExpr target_2, ExprStmt target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getExpr() |
		obj_0.getTarget().hasName("my_ok")
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vthd_1580
	)
	and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Function func, NotExpr target_2) {
	target_2.getOperand() instanceof FunctionCall
	and target_2.getEnclosingFunction() = func
}

from Function func, Parameter vthd_1580, FunctionCall target_0, ExprStmt target_1, NotExpr target_2
where
func_0(vthd_1580, target_1, target_0)
and func_1(vthd_1580, target_2, target_1)
and func_2(func, target_2)
and vthd_1580.getType().hasName("THD *")
and vthd_1580.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
