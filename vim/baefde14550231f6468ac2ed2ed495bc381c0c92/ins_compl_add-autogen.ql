/**
 * @name vim-baefde14550231f6468ac2ed2ed495bc381c0c92-ins_compl_add
 * @id cpp/vim/baefde14550231f6468ac2ed2ed495bc381c0c92/ins-compl-add
 * @description vim-baefde14550231f6468ac2ed2ed495bc381c0c92-src/insexpand.c-ins_compl_add CVE-2022-2344
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmatch_768, Parameter vlen_760, ReturnStmt target_2, LogicalAndExpr target_3) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cp_str"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatch_768
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_760
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("match_at_original_text")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmatch_768
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cp_str"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatch_768
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_760
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vmatch_768, Parameter vlen_760, ReturnStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cp_str"
		and target_1.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatch_768
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_760
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("match_at_original_text")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmatch_768
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cp_str"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatch_768
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_760
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(ReturnStmt target_2) {
		target_2.getExpr().(Literal).getValue()="2"
}

predicate func_3(Variable vmatch_768, Parameter vlen_760, LogicalAndExpr target_3) {
		target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("match_at_original_text")
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmatch_768
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cp_str"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatch_768
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_760
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getAnOperand() instanceof EqualityOperation
}

from Function func, Variable vmatch_768, Parameter vlen_760, EqualityOperation target_1, ReturnStmt target_2, LogicalAndExpr target_3
where
not func_0(vmatch_768, vlen_760, target_2, target_3)
and func_1(vmatch_768, vlen_760, target_2, target_1)
and func_2(target_2)
and func_3(vmatch_768, vlen_760, target_3)
and vmatch_768.getType().hasName("compl_T *")
and vlen_760.getType().hasName("int")
and vmatch_768.getParentScope+() = func
and vlen_760.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
