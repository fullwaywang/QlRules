/**
 * @name mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-Certifier__initialize_server_gtid_set_
 * @id cpp/mysql-server/64bbdd9b485884feda5ab193aa1e69a81b2926fe/certifierinitializeservergtidset
 * @description mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-plugin/group_replication/src/gcs_event_handlers.cc-Certifier__initialize_server_gtid_set_ mysql-#33025231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
	target_0.getExpr().(Literal).getValue()="0"
	and target_0.getExpr().getEnclosingFunction() = func
}

/*predicate func_1(Function func, Literal target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getParent() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					obj_3.getTarget().hasName("prio")
					and obj_3.getQualifier().(ConstructorCall).getType() instanceof VoidType
				)
				and obj_2.getTarget().hasName("errcode")
			)
		)
	)
	and target_1.getValue()="11462"
	and not target_1.getValue()="11464"
	and target_1.getEnclosingFunction() = func
}

*/
/*predicate func_2(Function func, Literal target_2) {
	exists(FunctionCall obj_0 | obj_0=target_2.getParent() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
						exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
							exists(FunctionCall obj_6 | obj_6=obj_5.getQualifier() |
								obj_6.getTarget().hasName("prio")
								and obj_6.getQualifier().(ConstructorCall).getType() instanceof VoidType
							)
							and obj_5.getTarget().hasName("errcode")
							and obj_5.getArgument(0).(Literal).getValue()="11462"
						)
						and obj_4.getTarget().hasName("subsys")
						and obj_4.getArgument(0).(StringLiteral).getValue()="Repl"
					)
					and obj_3.getTarget().hasName("component")
					and obj_3.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
				)
				and obj_2.getTarget().hasName("source_line")
			)
		)
	)
	and target_2.getValue()="412"
	and not target_2.getValue()="421"
	and target_2.getEnclosingFunction() = func
}

*/
predicate func_3(Variable v__FUNCTION__, FunctionCall target_27, FunctionCall target_28, Literal target_3) {
	exists(FunctionCall obj_0 | obj_0=target_3.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
						exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
							exists(FunctionCall obj_6 | obj_6=obj_5.getQualifier() |
								obj_6.getTarget().hasName("component")
								and obj_6.getQualifier().(FunctionCall).getTarget().hasName("subsys")
								and obj_6.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
							)
							and obj_5.getTarget().hasName("source_line")
							and obj_5.getArgument(0).(Literal).getValue()="412"
						)
						and obj_4.getTarget().hasName("source_file")
						and obj_4.getArgument(0) instanceof AddressOfExpr
					)
					and obj_3.getTarget().hasName("function")
					and obj_3.getArgument(0).(VariableAccess).getTarget()=v__FUNCTION__
				)
				and obj_2.getTarget().hasName("lookup_quoted")
				and obj_2.getArgument(1).(StringLiteral).getValue()="Plugin group_replication reported"
			)
		)
	)
	and target_3.getValue()="11462"
	and not target_3.getValue()="11464"
	and target_27.getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
	and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_28.getArgument(0).(VariableAccess).getLocation())
}

predicate func_4(Function func, Literal target_4) {
	exists(FunctionCall obj_0 | obj_0=target_4.getParent() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
						exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
							exists(FunctionCall obj_6 | obj_6=obj_5.getQualifier() |
								obj_6.getTarget().hasName("prio")
								and obj_6.getQualifier().(ConstructorCall).getType() instanceof VoidType
							)
							and obj_5.getTarget().hasName("errcode")
							and obj_5.getArgument(0).(Literal).getValue()="11463"
						)
						and obj_4.getTarget().hasName("subsys")
						and obj_4.getArgument(0).(StringLiteral).getValue()="Repl"
					)
					and obj_3.getTarget().hasName("component")
					and obj_3.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
				)
				and obj_2.getTarget().hasName("source_line")
			)
		)
	)
	and target_4.getValue()="420"
	and not target_4.getValue()="413"
	and target_4.getEnclosingFunction() = func
}

predicate func_5(Function func, Literal target_5) {
	exists(FunctionCall obj_0 | obj_0=target_5.getParent() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
						exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
							exists(FunctionCall obj_6 | obj_6=obj_5.getQualifier() |
								obj_6.getTarget().hasName("prio")
								and obj_6.getQualifier().(ConstructorCall).getType() instanceof VoidType
							)
							and obj_5.getTarget().hasName("errcode")
							and obj_5.getArgument(0).(Literal).getValue()="11464"
						)
						and obj_4.getTarget().hasName("subsys")
						and obj_4.getArgument(0).(StringLiteral).getValue()="Repl"
					)
					and obj_3.getTarget().hasName("component")
					and obj_3.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
				)
				and obj_2.getTarget().hasName("source_line")
			)
		)
	)
	and target_5.getValue()="428"
	and not target_5.getValue()="421"
	and target_5.getEnclosingFunction() = func
}

predicate func_6(Function func, Literal target_6) {
	exists(FunctionCall obj_0 | obj_0=target_6.getParent() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
						exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
							exists(FunctionCall obj_6 | obj_6=obj_5.getQualifier() |
								obj_6.getTarget().hasName("prio")
								and obj_6.getQualifier().(ConstructorCall).getType() instanceof VoidType
							)
							and obj_5.getTarget().hasName("errcode")
							and obj_5.getArgument(0).(Literal).getValue()="11465"
						)
						and obj_4.getTarget().hasName("subsys")
						and obj_4.getArgument(0).(StringLiteral).getValue()="Repl"
					)
					and obj_3.getTarget().hasName("component")
					and obj_3.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
				)
				and obj_2.getTarget().hasName("source_line")
			)
		)
	)
	and target_6.getValue()="437"
	and not target_6.getValue()="430"
	and target_6.getEnclosingFunction() = func
}

predicate func_7(Function func, Literal target_7) {
	exists(FunctionCall obj_0 | obj_0=target_7.getParent() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
						exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
							exists(FunctionCall obj_6 | obj_6=obj_5.getQualifier() |
								obj_6.getTarget().hasName("prio")
								and obj_6.getQualifier().(ConstructorCall).getType() instanceof VoidType
							)
							and obj_5.getTarget().hasName("errcode")
							and obj_5.getArgument(0).(Literal).getValue()="11466"
						)
						and obj_4.getTarget().hasName("subsys")
						and obj_4.getArgument(0).(StringLiteral).getValue()="Repl"
					)
					and obj_3.getTarget().hasName("component")
					and obj_3.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
				)
				and obj_2.getTarget().hasName("source_line")
			)
		)
	)
	and target_7.getValue()="446"
	and not target_7.getValue()="439"
	and target_7.getEnclosingFunction() = func
}

predicate func_8(Function func, ConstructorCall target_8) {
	target_8.getType() instanceof VoidType
	and target_8.getEnclosingFunction() = func
}

predicate func_11(Function func) {
exists(AssignExpr target_11 |
	exists(NewExpr obj_0 | obj_0=target_11.getRValue() |
		obj_0.getAllocatorCall() instanceof FunctionCall
		and obj_0.getInitializer().(ConstructorCall).getType() instanceof VoidType
	)
	and target_11.getLValue().(VariableAccess).getType().hasName("Get_system_variable *")
	and target_11.getEnclosingFunction() = func
)
}

predicate func_14(Function func, AddressOfExpr target_14) {
	exists(ArrayExpr obj_0 | obj_0=target_14.getOperand() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArrayOffset() |
			obj_1.getTarget().hasName("basename_index")
			and obj_1.getValue()="73"
		)
		and obj_0.getArrayBase().(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/plugin/group_replication/src/certifier.cc"
	)
	and exists(FunctionCall obj_2 | obj_2=target_14.getParent() |
		exists(FunctionCall obj_3 | obj_3=obj_2.getParent() |
			exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
				exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
					exists(FunctionCall obj_6 | obj_6=obj_5.getQualifier() |
						exists(FunctionCall obj_7 | obj_7=obj_6.getQualifier() |
							exists(FunctionCall obj_8 | obj_8=obj_7.getQualifier() |
								obj_8.getTarget().hasName("errcode")
								and obj_8.getQualifier().(FunctionCall).getTarget().hasName("prio")
								and obj_8.getArgument(0) instanceof Literal
							)
							and obj_7.getTarget().hasName("subsys")
							and obj_7.getArgument(0).(StringLiteral).getValue()="Repl"
						)
						and obj_6.getTarget().hasName("component")
						and obj_6.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
					)
					and obj_5.getTarget().hasName("source_line")
					and obj_5.getArgument(0) instanceof Literal
				)
				and obj_4.getTarget().hasName("source_file")
			)
		)
	)
	and target_14.getEnclosingFunction() = func
}

predicate func_16(Function func, AddressOfExpr target_16) {
	exists(ArrayExpr obj_0 | obj_0=target_16.getOperand() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArrayOffset() |
			obj_1.getTarget().hasName("basename_index")
			and obj_1.getValue()="73"
		)
		and obj_0.getArrayBase().(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/plugin/group_replication/src/certifier.cc"
	)
	and exists(FunctionCall obj_2 | obj_2=target_16.getParent() |
		exists(FunctionCall obj_3 | obj_3=obj_2.getParent() |
			exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
				exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
					exists(FunctionCall obj_6 | obj_6=obj_5.getQualifier() |
						exists(FunctionCall obj_7 | obj_7=obj_6.getQualifier() |
							exists(FunctionCall obj_8 | obj_8=obj_7.getQualifier() |
								obj_8.getTarget().hasName("errcode")
								and obj_8.getQualifier().(FunctionCall).getTarget().hasName("prio")
								and obj_8.getArgument(0).(Literal).getValue()="11463"
							)
							and obj_7.getTarget().hasName("subsys")
							and obj_7.getArgument(0).(StringLiteral).getValue()="Repl"
						)
						and obj_6.getTarget().hasName("component")
						and obj_6.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
					)
					and obj_5.getTarget().hasName("source_line")
					and obj_5.getArgument(0) instanceof Literal
				)
				and obj_4.getTarget().hasName("source_file")
			)
		)
	)
	and target_16.getEnclosingFunction() = func
}

predicate func_18(Function func, AddressOfExpr target_18) {
	exists(ArrayExpr obj_0 | obj_0=target_18.getOperand() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArrayOffset() |
			obj_1.getTarget().hasName("basename_index")
			and obj_1.getValue()="73"
		)
		and obj_0.getArrayBase().(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/plugin/group_replication/src/certifier.cc"
	)
	and exists(FunctionCall obj_2 | obj_2=target_18.getParent() |
		exists(FunctionCall obj_3 | obj_3=obj_2.getParent() |
			exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
				exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
					exists(FunctionCall obj_6 | obj_6=obj_5.getQualifier() |
						exists(FunctionCall obj_7 | obj_7=obj_6.getQualifier() |
							exists(FunctionCall obj_8 | obj_8=obj_7.getQualifier() |
								obj_8.getTarget().hasName("errcode")
								and obj_8.getQualifier().(FunctionCall).getTarget().hasName("prio")
								and obj_8.getArgument(0).(Literal).getValue()="11464"
							)
							and obj_7.getTarget().hasName("subsys")
							and obj_7.getArgument(0).(StringLiteral).getValue()="Repl"
						)
						and obj_6.getTarget().hasName("component")
						and obj_6.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
					)
					and obj_5.getTarget().hasName("source_line")
					and obj_5.getArgument(0) instanceof Literal
				)
				and obj_4.getTarget().hasName("source_file")
			)
		)
	)
	and target_18.getEnclosingFunction() = func
}

predicate func_20(Function func, AddressOfExpr target_20) {
	exists(ArrayExpr obj_0 | obj_0=target_20.getOperand() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArrayOffset() |
			obj_1.getTarget().hasName("basename_index")
			and obj_1.getValue()="73"
		)
		and obj_0.getArrayBase().(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/plugin/group_replication/src/certifier.cc"
	)
	and exists(FunctionCall obj_2 | obj_2=target_20.getParent() |
		exists(FunctionCall obj_3 | obj_3=obj_2.getParent() |
			exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
				exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
					exists(FunctionCall obj_6 | obj_6=obj_5.getQualifier() |
						exists(FunctionCall obj_7 | obj_7=obj_6.getQualifier() |
							exists(FunctionCall obj_8 | obj_8=obj_7.getQualifier() |
								obj_8.getTarget().hasName("errcode")
								and obj_8.getQualifier().(FunctionCall).getTarget().hasName("prio")
								and obj_8.getArgument(0).(Literal).getValue()="11465"
							)
							and obj_7.getTarget().hasName("subsys")
							and obj_7.getArgument(0).(StringLiteral).getValue()="Repl"
						)
						and obj_6.getTarget().hasName("component")
						and obj_6.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
					)
					and obj_5.getTarget().hasName("source_line")
					and obj_5.getArgument(0) instanceof Literal
				)
				and obj_4.getTarget().hasName("source_file")
			)
		)
	)
	and target_20.getEnclosingFunction() = func
}

predicate func_22(Function func, FunctionCall target_22) {
	target_22.getTarget().hasName("operator new")
	and target_22.getArgument(0).(ErrorExpr).getType() instanceof LongType
	and target_22.getEnclosingFunction() = func
}

predicate func_24(Variable vsql_command_interface_323, AssignExpr target_24) {
	exists(NewExpr obj_0 | obj_0=target_24.getRValue() |
		obj_0.getAllocatorCall() instanceof FunctionCall
		and obj_0.getInitializer() instanceof ConstructorCall
	)
	and target_24.getLValue().(VariableAccess).getTarget()=vsql_command_interface_323
}

predicate func_25(Variable v__FUNCTION__, Variable vsql_command_interface_323, Variable verror_322, Function func, IfStmt target_25) {
	exists(FunctionCall obj_0 | obj_0=target_25.getCondition() |
		obj_0.getTarget().hasName("establish_session_connection")
		and obj_0.getQualifier().(VariableAccess).getTarget()=vsql_command_interface_323
		and obj_0.getArgument(1).(StringLiteral).getValue()="mysql.session"
	)
	and exists(BlockStmt obj_1 | obj_1=target_25.getThen() |
		exists(ExprStmt obj_2 | obj_2=obj_1.getStmt(0) |
			exists(FunctionCall obj_3 | obj_3=obj_2.getExpr() |
				exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
					exists(FunctionCall obj_5 | obj_5=obj_4.getQualifier() |
						obj_5.getTarget().hasName("source_file")
						and obj_5.getQualifier().(FunctionCall).getTarget().hasName("source_line")
						and obj_5.getArgument(0) instanceof AddressOfExpr
					)
					and obj_4.getTarget().hasName("function")
					and obj_4.getArgument(0).(VariableAccess).getTarget()=v__FUNCTION__
				)
				and obj_3.getTarget().hasName("lookup_quoted")
				and obj_3.getArgument(0) instanceof Literal
				and obj_3.getArgument(1).(StringLiteral).getValue()="Plugin group_replication reported"
			)
		)
		and exists(ExprStmt obj_6 | obj_6=obj_1.getStmt(1) |
			exists(AssignExpr obj_7 | obj_7=obj_6.getExpr() |
				obj_7.getLValue().(VariableAccess).getTarget()=verror_322
				and obj_7.getRValue().(Literal).getValue()="1"
			)
		)
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_25
}

predicate func_26(Variable vsql_command_interface_323, FunctionCall target_29, VariableAccess target_26) {
	target_26.getTarget()=vsql_command_interface_323
	and target_29.getQualifier().(VariableAccess).getLocation().isBefore(target_26.getLocation())
}

predicate func_27(Variable v__FUNCTION__, FunctionCall target_27) {
	exists(FunctionCall obj_0 | obj_0=target_27.getQualifier() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getQualifier() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
						obj_4.getTarget().hasName("errcode")
						and obj_4.getQualifier().(FunctionCall).getTarget().hasName("prio")
						and obj_4.getArgument(0).(Literal).getValue()="13760"
					)
					and obj_3.getTarget().hasName("subsys")
					and obj_3.getArgument(0).(StringLiteral).getValue()="Repl"
				)
				and obj_2.getTarget().hasName("component")
				and obj_2.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
			)
			and obj_1.getTarget().hasName("source_line")
			and obj_1.getArgument(0).(Literal).getValue()="401"
		)
		and exists(AddressOfExpr obj_5 | obj_5=obj_0.getArgument(0) |
			exists(ArrayExpr obj_6 | obj_6=obj_5.getOperand() |
				exists(FunctionCall obj_7 | obj_7=obj_6.getArrayOffset() |
					obj_7.getTarget().hasName("basename_index")
					and obj_7.getValue()="73"
				)
				and obj_6.getArrayBase().(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/plugin/group_replication/src/certifier.cc"
			)
		)
		and obj_0.getTarget().hasName("source_file")
	)
	and target_27.getTarget().hasName("function")
	and target_27.getArgument(0).(VariableAccess).getTarget()=v__FUNCTION__
}

predicate func_28(Variable v__FUNCTION__, FunctionCall target_28) {
	exists(FunctionCall obj_0 | obj_0=target_28.getQualifier() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getQualifier() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
						obj_4.getTarget().hasName("errcode")
						and obj_4.getQualifier().(FunctionCall).getTarget().hasName("prio")
						and obj_4.getArgument(0).(Literal).getValue()="11463"
					)
					and obj_3.getTarget().hasName("subsys")
					and obj_3.getArgument(0).(StringLiteral).getValue()="Repl"
				)
				and obj_2.getTarget().hasName("component")
				and obj_2.getArgument(0).(StringLiteral).getValue()="plugin:group_replication"
			)
			and obj_1.getTarget().hasName("source_line")
			and obj_1.getArgument(0) instanceof Literal
		)
		and obj_0.getTarget().hasName("source_file")
		and obj_0.getArgument(0) instanceof AddressOfExpr
	)
	and target_28.getTarget().hasName("function")
	and target_28.getArgument(0).(VariableAccess).getTarget()=v__FUNCTION__
}

predicate func_29(Variable vsql_command_interface_323, FunctionCall target_29) {
	target_29.getTarget().hasName("establish_session_connection")
	and target_29.getQualifier().(VariableAccess).getTarget()=vsql_command_interface_323
	and target_29.getArgument(0) instanceof EnumConstantAccess
	and target_29.getArgument(1) instanceof StringLiteral
}

from Function func, Variable v__FUNCTION__, Variable vsql_command_interface_323, Variable verror_322, Initializer target_0, Literal target_3, Literal target_4, Literal target_5, Literal target_6, Literal target_7, ConstructorCall target_8, AddressOfExpr target_14, AddressOfExpr target_16, AddressOfExpr target_18, AddressOfExpr target_20, FunctionCall target_22, AssignExpr target_24, IfStmt target_25, VariableAccess target_26, FunctionCall target_27, FunctionCall target_28, FunctionCall target_29
where
func_0(func, target_0)
and func_3(v__FUNCTION__, target_27, target_28, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and func_6(func, target_6)
and func_7(func, target_7)
and func_8(func, target_8)
and not func_11(func)
and func_14(func, target_14)
and func_16(func, target_16)
and func_18(func, target_18)
and func_20(func, target_20)
and func_22(func, target_22)
and func_24(vsql_command_interface_323, target_24)
and func_25(v__FUNCTION__, vsql_command_interface_323, verror_322, func, target_25)
and func_26(vsql_command_interface_323, target_29, target_26)
and func_27(v__FUNCTION__, target_27)
and func_28(v__FUNCTION__, target_28)
and func_29(vsql_command_interface_323, target_29)
and v__FUNCTION__.getType().hasName("const StringLike<char[27], void>")
and vsql_command_interface_323.getType().hasName("Sql_service_command_interface *")
and verror_322.getType().hasName("int")
and not v__FUNCTION__.getParentScope+() = func
and vsql_command_interface_323.(LocalVariable).getFunction() = func
and verror_322.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
