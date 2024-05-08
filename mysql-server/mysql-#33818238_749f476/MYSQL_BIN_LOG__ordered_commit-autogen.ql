/**
 * @name mysql-server-749f476cf6c30cfda260355375a49263d13c2ab1-MYSQL_BIN_LOG__ordered_commit
 * @id cpp/mysql-server/749f476cf6c30cfda260355375a49263d13c2ab1/mysqlbinlogorderedcommit
 * @description mysql-server-749f476cf6c30cfda260355375a49263d13c2ab1-sql/binlog.cc-MYSQL_BIN_LOG__ordered_commit mysql-#33818238
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vflush_error_8798, Variable vupdate_binlog_end_pos_after_sync_8845, BlockStmt target_11, LogicalAndExpr target_12) {
exists(LogicalAndExpr target_0 |
	exists(EqualityOperation obj_0 | obj_0=target_0.getRightOperand() |
		obj_0.getLeftOperand().(VariableAccess).getTarget()=vflush_error_8798
		and obj_0.getRightOperand().(Literal).getValue()="0"
	)
	and exists(LogicalAndExpr obj_1 | obj_1=target_0.getParent() |
		exists(EqualityOperation obj_2 | obj_2=obj_1.getRightOperand() |
			obj_2.getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
			and obj_2.getRightOperand().(Literal).getValue()="0"
		)
		and obj_1.getLeftOperand() instanceof EqualityOperation
		and obj_1.getParent().(IfStmt).getThen()=target_11
	)
	and target_0.getLeftOperand().(VariableAccess).getTarget()=vupdate_binlog_end_pos_after_sync_8845
	and target_12.getLeftOperand().(EqualityOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(EqualityOperation).getLeftOperand().(VariableAccess).getLocation())
)
}

predicate func_2(Variable vtmp_thd_8934, LogicalAndExpr target_14) {
exists(IfStmt target_2 |
	exists(EqualityOperation obj_0 | obj_0=target_2.getCondition() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLeftOperand() |
			obj_1.getTarget().getName()="commit_error"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vtmp_thd_8934
		)
	)
	and exists(BlockStmt obj_2 | obj_2=target_2.getParent() |
		exists(IfStmt obj_3 | obj_3=obj_2.getParent() |
			obj_3.getThen().(BlockStmt).getStmt(0)=target_2
			and obj_3.getCondition()=target_14
		)
	)
	and target_2.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
)
}

predicate func_3(Variable vpos_8936, Variable vbinlog_file_8935, BlockStmt target_11, AddressOfExpr target_16, AddressOfExpr target_18) {
exists(LogicalAndExpr target_3 |
	exists(EqualityOperation obj_0 | obj_0=target_3.getLeftOperand() |
		obj_0.getLeftOperand().(VariableAccess).getTarget()=vbinlog_file_8935
		and obj_0.getRightOperand().(Literal).getValue()="0"
	)
	and exists(RelationalOperation obj_1 | obj_1=target_3.getRightOperand() |
		obj_1.getGreaterOperand().(VariableAccess).getTarget()=vpos_8936
		and obj_1.getLesserOperand().(Literal).getValue()="0"
	)
	and target_3.getParent().(IfStmt).getThen()=target_11
	and target_3.getRightOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_16.getOperand().(VariableAccess).getLocation())
	and target_3.getLeftOperand().(EqualityOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_18.getOperand().(VariableAccess).getLocation())
)
}

predicate func_4(Variable vflush_error_8798, BlockStmt target_11, EqualityOperation target_4) {
	exists(LogicalAndExpr obj_0 | obj_0=target_4.getParent() |
		exists(EqualityOperation obj_1 | obj_1=obj_0.getRightOperand() |
			obj_1.getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
			and obj_1.getRightOperand().(Literal).getValue()="0"
		)
		and obj_0.getParent().(IfStmt).getThen()=target_11
	)
	and target_4.getLeftOperand().(VariableAccess).getTarget()=vflush_error_8798
	and target_4.getRightOperand().(Literal).getValue()="0"
}

predicate func_5(Variable vtmp_thd_8934, EqualityOperation target_19, ExprStmt target_5) {
	exists(AssignExpr obj_0 | obj_0=target_5.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getRValue() |
			obj_1.getTarget().getName()="next_to_commit"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vtmp_thd_8934
		)
		and obj_0.getLValue().(VariableAccess).getTarget()=vtmp_thd_8934
	)
	and target_5.getParent().(WhileStmt).getCondition()=target_19
}

predicate func_6(Variable vpos_8936, Variable vtmp_thd_8934, Variable vbinlog_file_8935, LogicalAndExpr target_14, ExprStmt target_6) {
	exists(FunctionCall obj_0 | obj_0=target_6.getExpr() |
		obj_0.getTarget().hasName("get_trans_fixed_pos")
		and obj_0.getQualifier().(VariableAccess).getTarget()=vtmp_thd_8934
		and obj_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbinlog_file_8935
		and obj_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpos_8936
	)
	and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_7(Variable vpos_8936, Variable vbinlog_file_8935, LogicalAndExpr target_14, ExprStmt target_7) {
	exists(FunctionCall obj_0 | obj_0=target_7.getExpr() |
		obj_0.getTarget().hasName("update_binlog_end_pos")
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vbinlog_file_8935
		and obj_0.getArgument(1).(VariableAccess).getTarget()=vpos_8936
	)
	and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_8(Variable vtmp_thd_8934, VariableAccess target_8) {
	target_8.getTarget()=vtmp_thd_8934
}

predicate func_9(Variable vupdate_binlog_end_pos_after_sync_8845, BlockStmt target_20, VariableAccess target_9) {
	target_9.getTarget()=vupdate_binlog_end_pos_after_sync_8845
	and target_9.getParent().(IfStmt).getThen()=target_20
}

predicate func_10(Variable vtmp_thd_8934, PointerFieldAccess target_10) {
	target_10.getTarget().getName()="next_to_commit"
	and target_10.getQualifier().(VariableAccess).getTarget()=vtmp_thd_8934
}

predicate func_11(Function func, BlockStmt target_11) {
	target_11.getStmt(0) instanceof ExprStmt
	and target_11.getStmt(1) instanceof ExprStmt
	and target_11.getEnclosingFunction() = func
}

predicate func_12(Variable vflush_error_8798, BlockStmt target_21, LogicalAndExpr target_12) {
	exists(EqualityOperation obj_0 | obj_0=target_12.getLeftOperand() |
		obj_0.getLeftOperand().(VariableAccess).getTarget()=vflush_error_8798
		and obj_0.getRightOperand().(Literal).getValue()="0"
	)
	and exists(RelationalOperation obj_1 | obj_1=target_12.getRightOperand() |
		obj_1.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("my_off_t")
		and obj_1.getLesserOperand().(Literal).getValue()="0"
	)
	and target_12.getParent().(IfStmt).getThen()=target_21
}

predicate func_14(Function func, LogicalAndExpr target_14) {
	exists(EqualityOperation obj_0 | obj_0=target_14.getRightOperand() |
		obj_0.getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and obj_0.getRightOperand().(Literal).getValue()="0"
	)
	and target_14.getLeftOperand() instanceof EqualityOperation
	and target_14.getEnclosingFunction() = func
}

predicate func_16(Variable vpos_8936, AddressOfExpr target_16) {
	target_16.getOperand().(VariableAccess).getTarget()=vpos_8936
}

predicate func_18(Variable vbinlog_file_8935, AddressOfExpr target_18) {
	target_18.getOperand().(VariableAccess).getTarget()=vbinlog_file_8935
}

predicate func_19(Variable vtmp_thd_8934, EqualityOperation target_19) {
	exists(PointerFieldAccess obj_0 | obj_0=target_19.getLeftOperand() |
		obj_0.getTarget().getName()="next_to_commit"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vtmp_thd_8934
	)
	and target_19.getRightOperand().(Literal).getValue()="0"
}

predicate func_20(Variable vtmp_thd_8934, BlockStmt target_20) {
	exists(WhileStmt obj_0 | obj_0=target_20.getStmt(3) |
		exists(EqualityOperation obj_1 | obj_1=obj_0.getCondition() |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getLeftOperand() |
				obj_2.getTarget().getName()="next_to_commit"
				and obj_2.getQualifier().(VariableAccess).getTarget()=vtmp_thd_8934
			)
			and obj_1.getRightOperand().(Literal).getValue()="0"
		)
		and obj_0.getStmt() instanceof ExprStmt
	)
	and exists(IfStmt obj_3 | obj_3=target_20.getStmt(4) |
		exists(LogicalAndExpr obj_4 | obj_4=obj_3.getCondition() |
			exists(EqualityOperation obj_5 | obj_5=obj_4.getRightOperand() |
				obj_5.getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
				and obj_5.getRightOperand().(Literal).getValue()="0"
			)
			and obj_4.getLeftOperand() instanceof EqualityOperation
		)
		and exists(BlockStmt obj_6 | obj_6=obj_3.getThen() |
			obj_6.getStmt(0) instanceof ExprStmt
			and obj_6.getStmt(1) instanceof ExprStmt
		)
	)
}

predicate func_21(Function func, BlockStmt target_21) {
	exists(ExprStmt obj_0 | obj_0=target_21.getStmt(2) |
		exists(AssignExpr obj_1 | obj_1=obj_0.getExpr() |
			exists(ValueFieldAccess obj_2 | obj_2=obj_1.getRValue() |
				obj_2.getTarget().getName()="first"
				and obj_2.getQualifier().(VariableAccess).getTarget().getType().hasName("pair<bool, bool>")
			)
			and obj_1.getLValue().(VariableAccess).getTarget().getType().hasName("int")
		)
	)
	and target_21.getEnclosingFunction() = func
}

from Function func, Variable vpos_8936, Variable vflush_error_8798, Variable vupdate_binlog_end_pos_after_sync_8845, Variable vtmp_thd_8934, Variable vbinlog_file_8935, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, VariableAccess target_8, VariableAccess target_9, PointerFieldAccess target_10, BlockStmt target_11, LogicalAndExpr target_12, LogicalAndExpr target_14, AddressOfExpr target_16, AddressOfExpr target_18, EqualityOperation target_19, BlockStmt target_20, BlockStmt target_21
where
not func_0(vflush_error_8798, vupdate_binlog_end_pos_after_sync_8845, target_11, target_12)
and not func_2(vtmp_thd_8934, target_14)
and not func_3(vpos_8936, vbinlog_file_8935, target_11, target_16, target_18)
and func_4(vflush_error_8798, target_11, target_4)
and func_5(vtmp_thd_8934, target_19, target_5)
and func_6(vpos_8936, vtmp_thd_8934, vbinlog_file_8935, target_14, target_6)
and func_7(vpos_8936, vbinlog_file_8935, target_14, target_7)
and func_8(vtmp_thd_8934, target_8)
and func_9(vupdate_binlog_end_pos_after_sync_8845, target_20, target_9)
and func_10(vtmp_thd_8934, target_10)
and func_11(func, target_11)
and func_12(vflush_error_8798, target_21, target_12)
and func_14(func, target_14)
and func_16(vpos_8936, target_16)
and func_18(vbinlog_file_8935, target_18)
and func_19(vtmp_thd_8934, target_19)
and func_20(vtmp_thd_8934, target_20)
and func_21(func, target_21)
and vpos_8936.getType().hasName("my_off_t")
and vflush_error_8798.getType().hasName("int")
and vupdate_binlog_end_pos_after_sync_8845.getType().hasName("bool")
and vtmp_thd_8934.getType().hasName("THD *")
and vbinlog_file_8935.getType().hasName("const char *")
and vpos_8936.(LocalVariable).getFunction() = func
and vflush_error_8798.(LocalVariable).getFunction() = func
and vupdate_binlog_end_pos_after_sync_8845.(LocalVariable).getFunction() = func
and vtmp_thd_8934.(LocalVariable).getFunction() = func
and vbinlog_file_8935.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
