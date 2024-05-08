/**
 * @name mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-Certifier__initialize_server_gtid_set
 * @id cpp/mysql-server/64bbdd9b485884feda5ab193aa1e69a81b2926fe/certifierinitializeservergtidset
 * @description mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-plugin/group_replication/src/certifier.cc-Certifier__initialize_server_gtid_set mysql-#33025231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
	target_0.getExpr().(Literal).getValue()="0"
	and target_0.getExpr().getEnclosingFunction() = func
}

predicate func_1(Function func, ConstructorCall target_1) {
	target_1.getType() instanceof VoidType
	and target_1.getEnclosingFunction() = func
}

predicate func_4(Function func) {
exists(AssignExpr target_4 |
	exists(NewExpr obj_0 | obj_0=target_4.getRValue() |
		obj_0.getAllocatorCall() instanceof FunctionCall
		and obj_0.getInitializer().(ConstructorCall).getType() instanceof VoidType
	)
	and target_4.getLValue().(VariableAccess).getType().hasName("Get_system_variable *")
	and target_4.getEnclosingFunction() = func
)
}

predicate func_7(Variable verror_322, FunctionCall target_14, ExprStmt target_7) {
	exists(AssignExpr obj_0 | obj_0=target_7.getExpr() |
		obj_0.getLValue().(VariableAccess).getTarget()=verror_322
		and obj_0.getRValue().(Literal).getValue()="1"
	)
	and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_8(Function func, FunctionCall target_8) {
	target_8.getTarget().hasName("operator new")
	and target_8.getArgument(0).(ErrorExpr).getType() instanceof LongType
	and target_8.getEnclosingFunction() = func
}

predicate func_10(Variable vsql_command_interface_323, AssignExpr target_10) {
	exists(NewExpr obj_0 | obj_0=target_10.getRValue() |
		obj_0.getAllocatorCall() instanceof FunctionCall
		and obj_0.getInitializer() instanceof ConstructorCall
	)
	and target_10.getLValue().(VariableAccess).getTarget()=vsql_command_interface_323
}

predicate func_11(Variable vsql_command_interface_323, Variable v__FUNCTION__, Function func, IfStmt target_11) {
	exists(FunctionCall obj_0 | obj_0=target_11.getCondition() |
		obj_0.getTarget().hasName("establish_session_connection")
		and obj_0.getQualifier().(VariableAccess).getTarget()=vsql_command_interface_323
		and obj_0.getArgument(1).(StringLiteral).getValue()="mysql.session"
	)
	and exists(BlockStmt obj_1 | obj_1=target_11.getThen() |
		exists(ExprStmt obj_2 | obj_2=obj_1.getStmt(0) |
			exists(FunctionCall obj_3 | obj_3=obj_2.getExpr() |
				exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
					exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
						obj_5.getTarget().hasName("source_file")
						and obj_5.getQualifier().(FunctionCall).getTarget().hasName("source_line")
					)
					and obj_4.getTarget().hasName("function")
					and obj_4.getArgument(0).(VariableAccess).getTarget()=v__FUNCTION__
				)
				and obj_3.getTarget().hasName("lookup_quoted")
				and obj_3.getArgument(0) instanceof Literal
				and obj_3.getArgument(1).(StringLiteral).getValue()="Plugin group_replication reported"
			)
		)
		and obj_1.getStmt(1) instanceof ExprStmt
		and obj_1.getStmt(2).(GotoStmt).getName() ="end"
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

/*predicate func_12(FunctionCall target_14, Function func, GotoStmt target_12) {
	target_12.getName() ="end"
	and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
	and target_12.getEnclosingFunction() = func
}

*/
predicate func_13(Variable vsql_command_interface_323, FunctionCall target_14, VariableAccess target_13) {
	target_13.getTarget()=vsql_command_interface_323
	and target_14.getQualifier().(VariableAccess).getLocation().isBefore(target_13.getLocation())
}

predicate func_14(Variable vsql_command_interface_323, FunctionCall target_14) {
	target_14.getTarget().hasName("establish_session_connection")
	and target_14.getQualifier().(VariableAccess).getTarget()=vsql_command_interface_323
	and target_14.getArgument(0) instanceof EnumConstantAccess
	and target_14.getArgument(1) instanceof StringLiteral
}

from Function func, Variable verror_322, Variable vsql_command_interface_323, Variable v__FUNCTION__, Initializer target_0, ConstructorCall target_1, ExprStmt target_7, FunctionCall target_8, AssignExpr target_10, IfStmt target_11, VariableAccess target_13, FunctionCall target_14
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_4(func)
and func_7(verror_322, target_14, target_7)
and func_8(func, target_8)
and func_10(vsql_command_interface_323, target_10)
and func_11(vsql_command_interface_323, v__FUNCTION__, func, target_11)
and func_13(vsql_command_interface_323, target_14, target_13)
and func_14(vsql_command_interface_323, target_14)
and verror_322.getType().hasName("int")
and vsql_command_interface_323.getType().hasName("Sql_service_command_interface *")
and v__FUNCTION__.getType().hasName("const StringLike<char[27], void>")
and verror_322.(LocalVariable).getFunction() = func
and vsql_command_interface_323.(LocalVariable).getFunction() = func
and not v__FUNCTION__.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
