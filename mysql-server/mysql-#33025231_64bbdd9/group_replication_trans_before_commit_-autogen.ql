/**
 * @name mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-group_replication_trans_before_commit_
 * @id cpp/mysql-server/64bbdd9b485884feda5ab193aa1e69a81b2926fe/groupreplicationtransbeforecommit
 * @description mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-plugin/group_replication/src/plugin.cc-group_replication_trans_before_commit_ mysql-#33025231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="11599"
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
	and target_0.getValue()="233"
	and not target_0.getValue()="239"
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="11600"
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
	and target_1.getValue()="249"
	and not target_1.getValue()="255"
	and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
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
							and obj_5.getArgument(0).(Literal).getValue()="11601"
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
	and target_2.getValue()="256"
	and not target_2.getValue()="262"
	and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, Literal target_3) {
	exists(FunctionCall obj_0 | obj_0=target_3.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="11602"
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
	and target_3.getValue()="263"
	and not target_3.getValue()="269"
	and target_3.getEnclosingFunction() = func
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
							and obj_5.getArgument(0).(Literal).getValue()="11603"
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
	and target_4.getValue()="320"
	and not target_4.getValue()="326"
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
							and obj_5.getArgument(0).(Literal).getValue()="11605"
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
	and target_5.getValue()="341"
	and not target_5.getValue()="347"
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
							and obj_5.getArgument(0).(Literal).getValue()="11606"
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
	and target_6.getValue()="358"
	and not target_6.getValue()="364"
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
							and obj_5.getArgument(0).(Literal).getValue()="11607"
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
	and target_7.getValue()="368"
	and not target_7.getValue()="374"
	and target_7.getEnclosingFunction() = func
}

predicate func_8(Function func, Literal target_8) {
	exists(FunctionCall obj_0 | obj_0=target_8.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="11608"
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
	and target_8.getValue()="449"
	and not target_8.getValue()="455"
	and target_8.getEnclosingFunction() = func
}

predicate func_9(Function func, Literal target_9) {
	exists(FunctionCall obj_0 | obj_0=target_9.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="11611"
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
	and target_9.getValue()="477"
	and not target_9.getValue()="483"
	and target_9.getEnclosingFunction() = func
}

predicate func_10(Function func, Literal target_10) {
	exists(FunctionCall obj_0 | obj_0=target_10.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="11611"
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
	and target_10.getValue()="489"
	and not target_10.getValue()="495"
	and target_10.getEnclosingFunction() = func
}

predicate func_11(Function func, Literal target_11) {
	exists(FunctionCall obj_0 | obj_0=target_11.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="1041"
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
	and target_11.getValue()="494"
	and not target_11.getValue()="500"
	and target_11.getEnclosingFunction() = func
}

predicate func_12(Function func, Literal target_12) {
	exists(FunctionCall obj_0 | obj_0=target_12.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="11612"
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
	and target_12.getValue()="503"
	and not target_12.getValue()="509"
	and target_12.getEnclosingFunction() = func
}

predicate func_13(Function func, Literal target_13) {
	exists(FunctionCall obj_0 | obj_0=target_13.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="11613"
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
	and target_13.getValue()="537"
	and not target_13.getValue()="543"
	and target_13.getEnclosingFunction() = func
}

predicate func_14(Function func, Literal target_14) {
	exists(FunctionCall obj_0 | obj_0=target_14.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="11614"
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
	and target_14.getValue()="544"
	and not target_14.getValue()="550"
	and target_14.getEnclosingFunction() = func
}

predicate func_15(Function func, Literal target_15) {
	exists(FunctionCall obj_0 | obj_0=target_15.getParent() |
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
							and obj_5.getArgument(0).(Literal).getValue()="11615"
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
	and target_15.getValue()="556"
	and not target_15.getValue()="562"
	and target_15.getEnclosingFunction() = func
}

from Function func, Literal target_0, Literal target_1, Literal target_2, Literal target_3, Literal target_4, Literal target_5, Literal target_6, Literal target_7, Literal target_8, Literal target_9, Literal target_10, Literal target_11, Literal target_12, Literal target_13, Literal target_14, Literal target_15
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and func_6(func, target_6)
and func_7(func, target_7)
and func_8(func, target_8)
and func_9(func, target_9)
and func_10(func, target_10)
and func_11(func, target_11)
and func_12(func, target_12)
and func_13(func, target_13)
and func_14(func, target_14)
and func_15(func, target_15)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
