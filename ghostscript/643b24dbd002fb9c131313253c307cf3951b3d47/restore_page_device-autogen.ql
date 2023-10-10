/**
 * @name ghostscript-643b24dbd002fb9c131313253c307cf3951b3d47-restore_page_device
 * @id cpp/ghostscript/643b24dbd002fb9c131313253c307cf3951b3d47/restore-page-device
 * @description ghostscript-643b24dbd002fb9c131313253c307cf3951b3d47-psi/zdevice2.c-restore_page_device CVE-2018-16802
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
		target_0.getExpr().(Literal).getValue()="512"
		and target_0.getExpr().getEnclosingFunction() = func
}

predicate func_1(Function func, Initializer target_1) {
		target_1.getExpr().(ValueFieldAccess).getTarget().getName()="p"
		and target_1.getExpr().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_1.getExpr().getEnclosingFunction() = func
}

predicate func_2(Variable vmax_ops_282, BlockStmt target_20, VariableAccess target_2) {
		target_2.getTarget()=vmax_ops_282
		and target_2.getParent().(GTExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_2.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_20
}

predicate func_3(Variable vmax_ops_282, ReturnStmt target_15, VariableAccess target_3) {
		target_3.getTarget()=vmax_ops_282
		and target_3.getParent().(GEExpr).getLesserOperand() instanceof FunctionCall
		and target_3.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_15
}

predicate func_6(Variable vmax_ops_282, ReturnStmt target_15) {
	exists(AddExpr target_6 |
		target_6.getAnOperand().(VariableAccess).getType().hasName("int")
		and target_6.getAnOperand() instanceof FunctionCall
		and target_6.getParent().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vmax_ops_282
		and target_6.getParent().(GEExpr).getLesserOperand() instanceof FunctionCall
		and target_6.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_15)
}

predicate func_7(Function func) {
	exists(ValueFieldAccess target_7 |
		target_7.getTarget().getName()="intval"
		and target_7.getQualifier().(ValueFieldAccess).getTarget().getName()="value"
		and target_7.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="max_stack"
		and target_7.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand() instanceof ValueFieldAccess
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Parameter vpgs_old_255, Variable vLockSafetyParams_263, RelationalOperation target_18, FunctionCall target_21, LogicalAndExpr target_22) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="LockSafetyParams"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("gs_currentdevice")
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpgs_old_255
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vLockSafetyParams_263
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_21.getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_22.getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_9(Parameter vi_ctx_p_255, ReturnStmt target_15, ValueFieldAccess target_13) {
	exists(RelationalOperation target_9 |
		 (target_9 instanceof GEExpr or target_9 instanceof LEExpr)
		and target_9.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_9.getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("ref_stack_count")
		and target_9.getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="stack"
		and target_9.getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="exec_stack"
		and target_9.getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_255
		and target_9.getLesserOperand().(ValueFieldAccess).getTarget().getName()="intval"
		and target_9.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="value"
		and target_9.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="max_stack"
		and target_9.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="stack"
		and target_9.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="exec_stack"
		and target_9.getParent().(IfStmt).getThen()=target_15
		and target_13.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_10(Parameter vi_ctx_p_255, ValueFieldAccess target_13) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="exec_stack"
		and target_10.getQualifier().(VariableAccess).getTarget()=vi_ctx_p_255
		and target_13.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_11(Parameter vpgs_old_255, Variable vLockSafetyParams_263, RelationalOperation target_23) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="LockSafetyParams"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("gs_currentdevice")
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpgs_old_255
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vLockSafetyParams_263
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_11
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23)
}

predicate func_12(RelationalOperation target_23, Function func) {
	exists(ReturnStmt target_12 |
		target_12.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Parameter vi_ctx_p_255, ValueFieldAccess target_13) {
		target_13.getTarget().getName()="stack"
		and target_13.getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_13.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_255
}

predicate func_14(Parameter vi_ctx_p_255, Variable vmax_ops_282, ReturnStmt target_15, FunctionCall target_14) {
		target_14.getTarget().hasName("ref_stack_count")
		and target_14.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="stack"
		and target_14.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_14.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_255
		and target_14.getParent().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vmax_ops_282
		and target_14.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_15
}

predicate func_15(RelationalOperation target_23, Function func, ReturnStmt target_15) {
		target_15.getParent().(IfStmt).getCondition()=target_23
		and target_15.getEnclosingFunction() = func
}

predicate func_16(Parameter vi_ctx_p_255, VariableAccess target_16) {
		target_16.getTarget()=vi_ctx_p_255
}

predicate func_18(Parameter vi_ctx_p_255, Variable vop_281, Variable vmax_ops_282, BlockStmt target_20, RelationalOperation target_18) {
		 (target_18 instanceof GTExpr or target_18 instanceof LTExpr)
		and target_18.getGreaterOperand().(VariableAccess).getTarget()=vmax_ops_282
		and target_18.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vop_281
		and target_18.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getTarget().getName()="bot"
		and target_18.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_18.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_18.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_255
		and target_18.getParent().(IfStmt).getThen()=target_20
}

/*predicate func_19(Parameter vi_ctx_p_255, ValueFieldAccess target_13, PointerFieldAccess target_19) {
		target_19.getTarget().getName()="op_stack"
		and target_19.getQualifier().(VariableAccess).getTarget()=vi_ctx_p_255
		and target_13.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_20(Variable vmax_ops_282, BlockStmt target_20) {
		target_20.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmax_ops_282
		and target_20.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof FunctionCall
		and target_20.getStmt(0).(IfStmt).getThen() instanceof ReturnStmt
}

predicate func_21(Parameter vpgs_old_255, FunctionCall target_21) {
		target_21.getTarget().hasName("gs_gstate_client_data")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vpgs_old_255
}

predicate func_22(Variable vLockSafetyParams_263, LogicalAndExpr target_22) {
		target_22.getAnOperand().(VariableAccess).getTarget()=vLockSafetyParams_263
		and target_22.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("bool")
}

predicate func_23(Variable vmax_ops_282, RelationalOperation target_23) {
		 (target_23 instanceof GEExpr or target_23 instanceof LEExpr)
		and target_23.getGreaterOperand().(VariableAccess).getTarget()=vmax_ops_282
		and target_23.getLesserOperand() instanceof FunctionCall
}

from Function func, Parameter vi_ctx_p_255, Parameter vpgs_old_255, Variable vLockSafetyParams_263, Variable vop_281, Variable vmax_ops_282, Initializer target_0, Initializer target_1, VariableAccess target_2, VariableAccess target_3, ValueFieldAccess target_13, FunctionCall target_14, ReturnStmt target_15, VariableAccess target_16, RelationalOperation target_18, BlockStmt target_20, FunctionCall target_21, LogicalAndExpr target_22, RelationalOperation target_23
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(vmax_ops_282, target_20, target_2)
and func_3(vmax_ops_282, target_15, target_3)
and not func_6(vmax_ops_282, target_15)
and not func_7(func)
and not func_8(vpgs_old_255, vLockSafetyParams_263, target_18, target_21, target_22)
and not func_9(vi_ctx_p_255, target_15, target_13)
and not func_11(vpgs_old_255, vLockSafetyParams_263, target_23)
and not func_12(target_23, func)
and func_13(vi_ctx_p_255, target_13)
and func_14(vi_ctx_p_255, vmax_ops_282, target_15, target_14)
and func_15(target_23, func, target_15)
and func_16(vi_ctx_p_255, target_16)
and func_18(vi_ctx_p_255, vop_281, vmax_ops_282, target_20, target_18)
and func_20(vmax_ops_282, target_20)
and func_21(vpgs_old_255, target_21)
and func_22(vLockSafetyParams_263, target_22)
and func_23(vmax_ops_282, target_23)
and vi_ctx_p_255.getType().hasName("i_ctx_t *")
and vpgs_old_255.getType().hasName("const gs_gstate *")
and vLockSafetyParams_263.getType().hasName("bool")
and vop_281.getType().hasName("os_ptr")
and vmax_ops_282.getType().hasName("const int")
and vi_ctx_p_255.getFunction() = func
and vpgs_old_255.getFunction() = func
and vLockSafetyParams_263.(LocalVariable).getFunction() = func
and vop_281.(LocalVariable).getFunction() = func
and vmax_ops_282.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
