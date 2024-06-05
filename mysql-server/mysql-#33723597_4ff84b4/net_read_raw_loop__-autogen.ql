/**
 * @name mysql-server-4ff84b4470578773882d24bb1ec67c1a75b99eb9-net_read_raw_loop__
 * @id cpp/mysql-server/4ff84b4470578773882d24bb1ec67c1a75b99eb9/netreadrawloop
 * @description mysql-server-4ff84b4470578773882d24bb1ec67c1a75b99eb9-sql/conn_handler/init_net_server_extension.cc-net_read_raw_loop__ mysql-#33723597
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(WhileStmt target_7, Function func) {
exists(IfStmt target_0 |
	exists(ExprStmt obj_0 | obj_0=target_0.getThen() |
		exists(AssignExpr obj_1 | obj_1=obj_0.getExpr() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getRValue() |
				obj_2.getTarget().hasName("time")
				and obj_2.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("time_t")
			)
			and obj_1.getLValue().(VariableAccess).getType().hasName("time_t")
		)
	)
	and target_0.getCondition().(VariableAccess).getType().hasName("bool")
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
	and target_0.getLocation().isBefore(target_7.getLocation())
)
}

predicate func_2(Parameter vnet_1342, LogicalAndExpr target_8, FunctionCall target_9, PointerFieldAccess target_10) {
exists(IfStmt target_2 |
	exists(RelationalOperation obj_0 | obj_0=target_2.getCondition() |
		exists(SubExpr obj_1 | obj_1=obj_0.getGreaterOperand() |
			obj_1.getLeftOperand().(VariableAccess).getType().hasName("time_t")
			and obj_1.getRightOperand().(VariableAccess).getType().hasName("time_t")
		)
		and exists(PointerFieldAccess obj_2 | obj_2=obj_0.getLesserOperand() |
			obj_2.getTarget().getName()="read_timeout"
			and obj_2.getQualifier().(VariableAccess).getTarget()=vnet_1342
		)
	)
	and exists(BlockStmt obj_3 | obj_3=target_2.getThen() |
		exists(ExprStmt obj_4 | obj_4=obj_3.getStmt(0) |
			exists(AssignExpr obj_5 | obj_5=obj_4.getExpr() |
				obj_5.getLValue().(VariableAccess).getType().hasName("bool")
				and obj_5.getRValue().(Literal).getValue()="1"
			)
		)
	)
	and exists(BlockStmt obj_6 | obj_6=target_2.getParent() |
		exists(IfStmt obj_7 | obj_7=obj_6.getParent() |
			obj_7.getThen().(BlockStmt).getStmt(1)=target_2
			and obj_7.getCondition()=target_8
		)
	)
	and target_9.getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
	and target_2.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
)
}

predicate func_3(Parameter vnet_1342, Variable veof_1344, VariableAccess target_11, LogicalAndExpr target_8, ExprStmt target_5, ExprStmt target_12) {
exists(IfStmt target_3 |
	exists(LogicalAndExpr obj_0 | obj_0=target_3.getCondition() |
		exists(LogicalOrExpr obj_1 | obj_1=obj_0.getRightOperand() |
			obj_1.getLeftOperand() instanceof VariableCall
			and obj_1.getRightOperand().(VariableAccess).getType().hasName("bool")
		)
		and obj_0.getLeftOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=veof_1344
	)
	and exists(ExprStmt obj_2 | obj_2=target_3.getThen() |
		exists(AssignExpr obj_3 | obj_3=obj_2.getExpr() |
			exists(PointerFieldAccess obj_4 | obj_4=obj_3.getLValue() |
				obj_4.getTarget().getName()="last_errno"
				and obj_4.getQualifier().(VariableAccess).getTarget()=vnet_1342
			)
			and obj_3.getRValue().(Literal).getValue()="1159"
		)
	)
	and exists(BlockStmt obj_5 | obj_5=target_3.getParent() |
		exists(IfStmt obj_6 | obj_6=obj_5.getParent() |
			obj_6.getThen().(BlockStmt).getStmt(0)=target_3
			and obj_6.getCondition()=target_11
		)
	)
	and target_3.getElse() instanceof ExprStmt
	and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
	and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getCondition().(LogicalAndExpr).getLeftOperand().(NotExpr).getOperand().(VariableAccess).getLocation())
)
}

/*predicate func_4(Variable veof_1344, ExprStmt target_13) {
exists(LogicalOrExpr target_4 |
	exists(LogicalAndExpr obj_0 | obj_0=target_4.getParent() |
		obj_0.getLeftOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=veof_1344
		and obj_0.getRightOperand() instanceof VariableCall
		and obj_0.getParent().(IfStmt).getThen()=target_13
	)
	and target_4.getLeftOperand() instanceof VariableCall
	and target_4.getRightOperand().(VariableAccess).getType().hasName("bool")
)
}

*/
predicate func_5(Parameter vnet_1342, LogicalAndExpr target_8, ExprStmt target_5) {
	exists(AssignExpr obj_0 | obj_0=target_5.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			obj_1.getTarget().getName()="last_errno"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vnet_1342
		)
		and obj_0.getRValue().(Literal).getValue()="1158"
	)
	and target_5.getParent().(IfStmt).getCondition()=target_8
}

predicate func_6(Parameter vnet_1342, VariableCall target_6) {
	exists(PointerFieldAccess obj_0 | obj_0=target_6.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="vio"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vnet_1342
		)
		and obj_0.getTarget().getName()="was_timeout"
	)
	and exists(PointerFieldAccess obj_2 | obj_2=target_6.getArgument(0) |
		obj_2.getTarget().getName()="vio"
		and obj_2.getQualifier().(VariableAccess).getTarget()=vnet_1342
	)
}

predicate func_7(Parameter vnet_1342, WhileStmt target_7) {
	exists(BlockStmt obj_0 | obj_0=target_7.getStmt() |
		exists(IfStmt obj_1 | obj_1=obj_0.getStmt(1) |
			exists(EqualityOperation obj_2 | obj_2=obj_1.getCondition() |
				obj_2.getLeftOperand().(VariableAccess).getTarget().getType().hasName("size_t")
				and obj_2.getRightOperand().(UnaryMinusExpr).getValue()="18446744073709551615"
			)
			and exists(BlockStmt obj_3 | obj_3=obj_1.getThen() |
				exists(IfStmt obj_4 | obj_4=obj_3.getStmt(0) |
					exists(FunctionCall obj_5 | obj_5=obj_4.getCondition() |
						obj_5.getTarget().hasName("net_should_retry")
						and obj_5.getArgument(0).(VariableAccess).getTarget()=vnet_1342
					)
				)
			)
			and obj_1.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("size_t")
		)
	)
	and target_7.getCondition().(VariableAccess).getTarget().getType().hasName("size_t")
}

predicate func_8(Variable veof_1344, LogicalAndExpr target_8) {
	target_8.getLeftOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=veof_1344
	and target_8.getRightOperand() instanceof VariableCall
}

predicate func_9(Parameter vnet_1342, FunctionCall target_9) {
	target_9.getTarget().hasName("net_should_retry")
	and target_9.getArgument(0).(VariableAccess).getTarget()=vnet_1342
	and target_9.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("unsigned int")
}

predicate func_10(Parameter vnet_1342, PointerFieldAccess target_10) {
	exists(PointerFieldAccess obj_0 | obj_0=target_10.getQualifier() |
		obj_0.getTarget().getName()="vio"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vnet_1342
	)
	and target_10.getTarget().getName()="was_timeout"
}

predicate func_11(Parameter vcount_1342, BlockStmt target_14, VariableAccess target_11) {
	target_11.getTarget()=vcount_1342
	and target_11.getParent().(IfStmt).getThen()=target_14
}

predicate func_12(Variable veof_1344, ExprStmt target_12) {
	exists(AssignExpr obj_0 | obj_0=target_12.getExpr() |
		obj_0.getLValue().(VariableAccess).getTarget()=veof_1344
		and obj_0.getRValue().(Literal).getValue()="1"
	)
}

predicate func_13(Parameter vnet_1342, ExprStmt target_13) {
	exists(AssignExpr obj_0 | obj_0=target_13.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			obj_1.getTarget().getName()="last_errno"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vnet_1342
		)
		and obj_0.getRValue().(Literal).getValue()="1159"
	)
}

predicate func_14(Parameter vnet_1342, Variable veof_1344, BlockStmt target_14) {
	exists(IfStmt obj_0 | obj_0=target_14.getStmt(0) |
		exists(LogicalAndExpr obj_1 | obj_1=obj_0.getCondition() |
			obj_1.getLeftOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=veof_1344
			and obj_1.getRightOperand() instanceof VariableCall
		)
		and exists(ExprStmt obj_2 | obj_2=obj_0.getThen() |
			exists(AssignExpr obj_3 | obj_3=obj_2.getExpr() |
				exists(PointerFieldAccess obj_4 | obj_4=obj_3.getLValue() |
					obj_4.getTarget().getName()="last_errno"
					and obj_4.getQualifier().(VariableAccess).getTarget()=vnet_1342
				)
				and obj_3.getRValue().(Literal).getValue()="1159"
			)
		)
		and obj_0.getElse() instanceof ExprStmt
	)
}

from Function func, Parameter vnet_1342, Parameter vcount_1342, Variable veof_1344, ExprStmt target_5, VariableCall target_6, WhileStmt target_7, LogicalAndExpr target_8, FunctionCall target_9, PointerFieldAccess target_10, VariableAccess target_11, ExprStmt target_12, ExprStmt target_13, BlockStmt target_14
where
not func_0(target_7, func)
and not func_2(vnet_1342, target_8, target_9, target_10)
and not func_3(vnet_1342, veof_1344, target_11, target_8, target_5, target_12)
and func_5(vnet_1342, target_8, target_5)
and func_6(vnet_1342, target_6)
and func_7(vnet_1342, target_7)
and func_8(veof_1344, target_8)
and func_9(vnet_1342, target_9)
and func_10(vnet_1342, target_10)
and func_11(vcount_1342, target_14, target_11)
and func_12(veof_1344, target_12)
and func_13(vnet_1342, target_13)
and func_14(vnet_1342, veof_1344, target_14)
and vnet_1342.getType().hasName("NET *")
and vcount_1342.getType().hasName("size_t")
and veof_1344.getType().hasName("bool")
and vnet_1342.getFunction() = func
and vcount_1342.getFunction() = func
and veof_1344.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
