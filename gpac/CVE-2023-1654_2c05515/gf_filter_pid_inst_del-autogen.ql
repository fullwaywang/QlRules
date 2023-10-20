/**
 * @name gpac-2c055153d401b8c49422971e3a0159869652d3da-gf_filter_pid_inst_del
 * @id cpp/gpac/2c055153d401b8c49422971e3a0159869652d3da/gf-filter-pid-inst-del
 * @description gpac-2c055153d401b8c49422971e3a0159869652d3da-src/filter_core/filter_pid.c-gf_filter_pid_inst_del CVE-2023-1654
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpidinst_55, BlockStmt target_7, IfStmt target_8, AddressOfExpr target_9) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(FunctionCall).getTarget().hasName("gf_list_find")
		and target_0.getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="properties"
		and target_0.getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pid"
		and target_0.getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpidinst_55
		and target_0.getGreaterOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="props"
		and target_0.getGreaterOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpidinst_55
		and target_0.getLesserOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_7
		and target_8.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_2, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition() instanceof EqualityOperation
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vpidinst_55, BlockStmt target_7, EqualityOperation target_2) {
		target_2.getAnOperand().(FunctionCall).getTarget().hasName("__sync_sub_and_fetch_4")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="reference_count"
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="props"
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpidinst_55
		and target_2.getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_7
}

predicate func_3(Parameter vpidinst_55, EqualityOperation target_2, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("gf_mx_p")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tasks_mx"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="filter"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pid"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpidinst_55
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_4(Parameter vpidinst_55, EqualityOperation target_2, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("gf_list_del_item")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="properties"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pid"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpidinst_55
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="props"
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpidinst_55
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_5(Parameter vpidinst_55, EqualityOperation target_2, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("gf_mx_v")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tasks_mx"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="filter"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pid"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpidinst_55
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_6(Parameter vpidinst_55, EqualityOperation target_2, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("gf_props_del")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="props"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpidinst_55
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_7(BlockStmt target_7) {
		target_7.getStmt(0) instanceof ExprStmt
		and target_7.getStmt(1) instanceof ExprStmt
		and target_7.getStmt(2) instanceof ExprStmt
		and target_7.getStmt(3) instanceof ExprStmt
}

predicate func_8(Parameter vpidinst_55, IfStmt target_8) {
		target_8.getCondition().(PointerFieldAccess).getTarget().getName()="props"
		and target_8.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpidinst_55
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition() instanceof EqualityOperation
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
}

predicate func_9(Parameter vpidinst_55, AddressOfExpr target_9) {
		target_9.getOperand().(PointerFieldAccess).getTarget().getName()="reference_count"
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="props"
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpidinst_55
}

from Function func, Parameter vpidinst_55, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, BlockStmt target_7, IfStmt target_8, AddressOfExpr target_9
where
not func_0(vpidinst_55, target_7, target_8, target_9)
and not func_1(target_2, func)
and func_2(vpidinst_55, target_7, target_2)
and func_3(vpidinst_55, target_2, target_3)
and func_4(vpidinst_55, target_2, target_4)
and func_5(vpidinst_55, target_2, target_5)
and func_6(vpidinst_55, target_2, target_6)
and func_7(target_7)
and func_8(vpidinst_55, target_8)
and func_9(vpidinst_55, target_9)
and vpidinst_55.getType().hasName("GF_FilterPidInst *")
and vpidinst_55.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
