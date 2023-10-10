/**
 * @name ghostscript-2a3129365d3bc0d4a41f107ef175920d1505d1f7-sampled_data_continue
 * @id cpp/ghostscript/2a3129365d3bc0d4a41f107ef175920d1505d1f7/sampled-data-continue
 * @description ghostscript-2a3129365d3bc0d4a41f107ef175920d1505d1f7-psi/zfsample.c-sampled_data_continue CVE-2021-45949
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ref_stack_pop")
		and target_0.getArgument(0).(AddressOfExpr).getOperand() instanceof ValueFieldAccess
		and target_0.getArgument(1) instanceof Literal
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("ref_stack_pop")
		and target_1.getArgument(0).(AddressOfExpr).getOperand() instanceof ValueFieldAccess
		and target_1.getArgument(1) instanceof SubExpr
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vstack_depth_adjust_488, RelationalOperation target_25, RelationalOperation target_26) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("ref_stack_pop")
		and target_2.getArgument(0).(AddressOfExpr).getOperand() instanceof ValueFieldAccess
		and target_2.getArgument(1).(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_25.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getArgument(1).(VariableAccess).getLocation())
		and target_2.getArgument(1).(VariableAccess).getLocation().isBefore(target_26.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vi_ctx_p_478, ValueFieldAccess target_27) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="op_stack"
		and target_3.getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
		and target_3.getQualifier().(VariableAccess).getLocation().isBefore(target_27.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Function func) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("ref_stack_push")
		and target_4.getArgument(0).(AddressOfExpr).getOperand() instanceof ValueFieldAccess
		and target_4.getArgument(1) instanceof SubExpr
		and target_4.getEnclosingFunction() = func)
}

/*predicate func_5(Parameter vi_ctx_p_478, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="op_stack"
		and target_5.getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
}

*/
/*predicate func_6(Parameter vi_ctx_p_478, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="op_stack"
		and target_6.getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
}

*/
/*predicate func_7(Parameter vi_ctx_p_478, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="op_stack"
		and target_7.getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
}

*/
predicate func_8(Parameter vi_ctx_p_478, ValueFieldAccess target_8) {
		target_8.getTarget().getName()="stack"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
}

predicate func_9(Parameter vi_ctx_p_478, ValueFieldAccess target_9) {
		target_9.getTarget().getName()="stack"
		and target_9.getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
}

predicate func_10(Variable vnum_out_484, Variable vstack_depth_adjust_488, SubExpr target_10) {
		target_10.getLeftOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_10.getRightOperand().(VariableAccess).getTarget()=vnum_out_484
}

predicate func_11(Parameter vi_ctx_p_478, ValueFieldAccess target_11) {
		target_11.getTarget().getName()="stack"
		and target_11.getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
}

predicate func_12(Variable vstack_depth_adjust_488, SubExpr target_12) {
		target_12.getLeftOperand().(Literal).getValue()="3"
		and target_12.getRightOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
}

predicate func_13(Parameter vi_ctx_p_478, ValueFieldAccess target_13) {
		target_13.getTarget().getName()="stack"
		and target_13.getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_13.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
}

predicate func_14(Parameter vi_ctx_p_478, PointerFieldAccess target_14) {
		target_14.getTarget().getName()="op_stack"
		and target_14.getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
}

predicate func_15(Parameter vi_ctx_p_478, PointerFieldAccess target_15) {
		target_15.getTarget().getName()="op_stack"
		and target_15.getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
}

predicate func_17(Variable vstack_depth_adjust_488, VariableAccess target_17) {
		target_17.getTarget()=vstack_depth_adjust_488
}

predicate func_18(Function func, AssignPointerSubExpr target_18) {
		target_18.getLValue().(ValueFieldAccess).getTarget().getName()="p"
		and target_18.getLValue().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_18.getRValue() instanceof Literal
		and target_18.getEnclosingFunction() = func
}

predicate func_19(Function func, AssignPointerSubExpr target_19) {
		target_19.getLValue().(ValueFieldAccess).getTarget().getName()="p"
		and target_19.getLValue().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_19.getRValue() instanceof SubExpr
		and target_19.getEnclosingFunction() = func
}

predicate func_20(Variable vstack_depth_adjust_488, AssignPointerSubExpr target_20) {
		target_20.getLValue().(ValueFieldAccess).getTarget().getName()="p"
		and target_20.getLValue().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_20.getRValue().(VariableAccess).getTarget()=vstack_depth_adjust_488
}

predicate func_21(Variable vop_480, RelationalOperation target_28, DoStmt target_21) {
		target_21.getCondition().(Literal).getValue()="0"
		and target_21.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vop_480
		and target_21.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AssignPointerAddExpr).getRValue() instanceof SubExpr
		and target_21.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="top"
		and target_21.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_21.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="requested"
		and target_21.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="p"
		and target_21.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_21.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vop_480
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_28
}

/*predicate func_22(Variable vop_480, Variable vstack_depth_adjust_488, Parameter vi_ctx_p_478, IfStmt target_22) {
		target_22.getCondition().(RelationalOperation).getGreaterOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vop_480
		and target_22.getCondition().(RelationalOperation).getGreaterOperand().(AssignPointerAddExpr).getRValue() instanceof SubExpr
		and target_22.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="top"
		and target_22.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="requested"
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="3"
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_22.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="p"
		and target_22.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_22.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_22.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
		and target_22.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vop_480
}

*/
/*predicate func_23(Variable vstack_depth_adjust_488, Parameter vi_ctx_p_478, RelationalOperation target_29, AssignExpr target_23) {
		target_23.getLValue().(ValueFieldAccess).getTarget().getName()="requested"
		and target_23.getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_23.getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_23.getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
		and target_23.getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="3"
		and target_23.getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_23.getRValue().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_29.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_24(RelationalOperation target_30, Function func, ReturnStmt target_24) {
		target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_30
		and target_24.getEnclosingFunction() = func
}

*/
predicate func_25(Variable vop_480, Variable vstack_depth_adjust_488, Parameter vi_ctx_p_478, RelationalOperation target_25) {
		 (target_25 instanceof GTExpr or target_25 instanceof LTExpr)
		and target_25.getLesserOperand().(VariableAccess).getTarget()=vop_480
		and target_25.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="bot"
		and target_25.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_25.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_25.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
		and target_25.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_25.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_26(Variable vstack_depth_adjust_488, Parameter vi_ctx_p_478, RelationalOperation target_26) {
		 (target_26 instanceof GTExpr or target_26 instanceof LTExpr)
		and target_26.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(ValueFieldAccess).getTarget().getName()="top"
		and target_26.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_26.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_26.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
		and target_26.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getTarget().getName()="p"
		and target_26.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_26.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_26.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
		and target_26.getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="3"
		and target_26.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
}

predicate func_27(Parameter vi_ctx_p_478, ValueFieldAccess target_27) {
		target_27.getTarget().getName()="stack"
		and target_27.getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_27.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_478
}

predicate func_28(Variable vstack_depth_adjust_488, RelationalOperation target_28) {
		 (target_28 instanceof GTExpr or target_28 instanceof LTExpr)
		and target_28.getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="3"
		and target_28.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_28.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_29(Variable vstack_depth_adjust_488, RelationalOperation target_29) {
		 (target_29 instanceof GTExpr or target_29 instanceof LTExpr)
		and target_29.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_29.getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="3"
		and target_29.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
}

predicate func_30(RelationalOperation target_30) {
		 (target_30 instanceof GTExpr or target_30 instanceof LTExpr)
		and target_30.getGreaterOperand() instanceof AssignPointerAddExpr
		and target_30.getLesserOperand() instanceof ValueFieldAccess
}

from Function func, Variable vop_480, Variable vnum_out_484, Variable vstack_depth_adjust_488, Parameter vi_ctx_p_478, ValueFieldAccess target_8, ValueFieldAccess target_9, SubExpr target_10, ValueFieldAccess target_11, SubExpr target_12, ValueFieldAccess target_13, PointerFieldAccess target_14, PointerFieldAccess target_15, VariableAccess target_17, AssignPointerSubExpr target_18, AssignPointerSubExpr target_19, AssignPointerSubExpr target_20, DoStmt target_21, RelationalOperation target_25, RelationalOperation target_26, ValueFieldAccess target_27, RelationalOperation target_28, RelationalOperation target_29, RelationalOperation target_30
where
not func_0(func)
and not func_1(func)
and not func_2(vstack_depth_adjust_488, target_25, target_26)
and not func_3(vi_ctx_p_478, target_27)
and not func_4(func)
and func_8(vi_ctx_p_478, target_8)
and func_9(vi_ctx_p_478, target_9)
and func_10(vnum_out_484, vstack_depth_adjust_488, target_10)
and func_11(vi_ctx_p_478, target_11)
and func_12(vstack_depth_adjust_488, target_12)
and func_13(vi_ctx_p_478, target_13)
and func_14(vi_ctx_p_478, target_14)
and func_15(vi_ctx_p_478, target_15)
and func_17(vstack_depth_adjust_488, target_17)
and func_18(func, target_18)
and func_19(func, target_19)
and func_20(vstack_depth_adjust_488, target_20)
and func_21(vop_480, target_28, target_21)
and func_25(vop_480, vstack_depth_adjust_488, vi_ctx_p_478, target_25)
and func_26(vstack_depth_adjust_488, vi_ctx_p_478, target_26)
and func_27(vi_ctx_p_478, target_27)
and func_28(vstack_depth_adjust_488, target_28)
and func_29(vstack_depth_adjust_488, target_29)
and func_30(target_30)
and vop_480.getType().hasName("os_ptr")
and vnum_out_484.getType().hasName("int")
and vstack_depth_adjust_488.getType().hasName("int")
and vi_ctx_p_478.getType().hasName("i_ctx_t *")
and vop_480.(LocalVariable).getFunction() = func
and vnum_out_484.(LocalVariable).getFunction() = func
and vstack_depth_adjust_488.(LocalVariable).getFunction() = func
and vi_ctx_p_478.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
