/**
 * @name mysql-server-44e4da61d1d1341ecf2b74a99acbc357ca3357cf-init_rsa_keys
 * @id cpp/mysql-server/44e4da61d1d1341ecf2b74a99acbc357ca3357cf/initrsakeys
 * @description mysql-server-44e4da61d1d1341ecf2b74a99acbc357ca3357cf-sql/auth/sql_authentication.cc-init_rsa_keys mysql-#34274914
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(IfStmt target_1, Function func) {
exists(IfStmt target_0 |
	exists(LogicalOrExpr obj_0 | obj_0=target_0.getCondition() |
		exists(LogicalAndExpr obj_1 | obj_1=obj_0.getLeftOperand() |
			exists(EqualityOperation obj_2 | obj_2=obj_1.getLeftOperand() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getLeftOperand() |
					obj_3.getTarget().hasName("strcmp")
					and obj_3.getArgument(0).(VariableAccess).getType().hasName("char *")
					and obj_3.getArgument(1).(StringLiteral).getValue()="private_key.pem"
				)
				and obj_2.getRightOperand().(Literal).getValue()="0"
			)
			and exists(EqualityOperation obj_4 | obj_4=obj_1.getRightOperand() |
				exists(FunctionCall obj_5 | obj_5=obj_4.getLeftOperand() |
					obj_5.getTarget().hasName("strcmp")
					and obj_5.getArgument(0).(VariableAccess).getType().hasName("char *")
					and obj_5.getArgument(1).(StringLiteral).getValue()="public_key.pem"
				)
				and obj_4.getRightOperand().(Literal).getValue()="0"
			)
		)
		and exists(LogicalAndExpr obj_6 | obj_6=obj_0.getRightOperand() |
			exists(EqualityOperation obj_7 | obj_7=obj_6.getLeftOperand() |
				exists(FunctionCall obj_8 | obj_8=obj_7.getLeftOperand() |
					obj_8.getTarget().hasName("strcmp")
					and obj_8.getArgument(0).(VariableAccess).getType().hasName("char *")
					and obj_8.getArgument(1).(StringLiteral).getValue()="private_key.pem"
				)
				and obj_7.getRightOperand().(Literal).getValue()="0"
			)
			and exists(EqualityOperation obj_9 | obj_9=obj_6.getRightOperand() |
				exists(FunctionCall obj_10 | obj_10=obj_9.getLeftOperand() |
					obj_10.getTarget().hasName("strcmp")
					and obj_10.getArgument(0).(VariableAccess).getType().hasName("char *")
					and obj_10.getArgument(1).(StringLiteral).getValue()="public_key.pem"
				)
				and obj_9.getRightOperand().(Literal).getValue()="0"
			)
		)
	)
	and exists(BlockStmt obj_11 | obj_11=target_0.getThen() |
		exists(IfStmt obj_12 | obj_12=obj_11.getStmt(0) |
			exists(LogicalAndExpr obj_13 | obj_13=obj_12.getCondition() |
				exists(EqualityOperation obj_14 | obj_14=obj_13.getLeftOperand() |
					exists(FunctionCall obj_15 | obj_15=obj_14.getLeftOperand() |
						obj_15.getTarget().hasName("access")
						and obj_15.getArgument(0).(StringLiteral).getValue()="private_key.pem"
						and obj_15.getArgument(1).(Literal).getValue()="0"
					)
					and obj_14.getRightOperand().(Literal).getValue()="0"
				)
				and exists(EqualityOperation obj_16 | obj_16=obj_13.getRightOperand() |
					exists(FunctionCall obj_17 | obj_17=obj_16.getLeftOperand() |
						obj_17.getTarget().hasName("access")
						and obj_17.getArgument(0).(StringLiteral).getValue()="public_key.pem"
						and obj_17.getArgument(1).(Literal).getValue()="0"
					)
					and obj_16.getRightOperand().(UnaryMinusExpr).getValue()="-1"
				)
			)
			and obj_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("remove")
		)
		and exists(ExprStmt obj_18 | obj_18=obj_11.getStmt(1) |
			exists(FunctionCall obj_19 | obj_19=obj_18.getExpr() |
				exists(FunctionCall obj_20 | obj_20=obj_19.getArgument(0) |
					exists(FunctionCall obj_21 | obj_21=obj_20.getQualifier() |
						obj_21.getTarget().hasName("operator+")
						and obj_21.getArgument(1).(StringLiteral).getValue()=".temp"
					)
					and obj_20.getTarget().hasName("c_str")
				)
				and obj_19.getTarget().hasName("remove")
			)
		)
		and exists(ExprStmt obj_22 | obj_22=obj_11.getStmt(2) |
			exists(FunctionCall obj_23 | obj_23=obj_22.getExpr() |
				exists(FunctionCall obj_24 | obj_24=obj_23.getArgument(0) |
					exists(FunctionCall obj_25 | obj_25=obj_24.getQualifier() |
						obj_25.getTarget().hasName("operator+")
						and obj_25.getArgument(1).(StringLiteral).getValue()=".temp"
					)
					and obj_24.getTarget().hasName("c_str")
				)
				and obj_23.getTarget().hasName("remove")
			)
		)
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
	and target_0.getLocation().isBefore(target_1.getLocation())
)
}

predicate func_1(Function func, IfStmt target_1) {
	target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("do_auto_rsa_keys_generation")
	and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
	and target_1.getEnclosingFunction() = func
}

from Function func, IfStmt target_1
where
not func_0(target_1, func)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
