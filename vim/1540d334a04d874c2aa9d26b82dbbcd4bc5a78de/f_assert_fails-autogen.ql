/**
 * @name vim-1540d334a04d874c2aa9d26b82dbbcd4bc5a78de-f_assert_fails
 * @id cpp/vim/1540d334a04d874c2aa9d26b82dbbcd4bc5a78de/f-assert-fails
 * @description vim-1540d334a04d874c2aa9d26b82dbbcd4bc5a78de-src/testing.c-f_assert_fails CVE-2022-3153
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vexpected_631, BlockStmt target_8, ExprStmt target_9, NotExpr target_6) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vexpected_631
		and target_0.getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_8
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(NotExpr target_6, Function func) {
	exists(GotoStmt target_1 |
		target_1.toString() = "goto ..."
		and target_1.getName() ="theend"
		and target_1.getParent().(IfStmt).getCondition()=target_6
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vbuf_630, Variable vexpected_631, Variable vexpected_str_632, Variable verror_found_633, Variable vactual_635, Variable vtv_647, EqualityOperation target_10, ExprStmt target_9, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, LogicalAndExpr target_14, EqualityOperation target_7, ExprStmt target_15) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof EqualityOperation
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtv_647
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="li_tv"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="lv_last"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexpected_631
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tv_get_string_buf_chk")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtv_647
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_630
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vexpected_631
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(GotoStmt).getName() ="theend"
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("pattern_match")
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpected_631
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vactual_635
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_found_633
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexpected_str_632
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vexpected_631
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation())
		and target_7.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vexpected_631, EqualityOperation target_7, ExprStmt target_16, NotExpr target_17) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vexpected_631
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(GotoStmt).toString() = "goto ..."
		and target_3.getThen().(GotoStmt).getName() ="theend"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_17.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_4(Variable vsave_trylevel_597, Variable vtrylevel, ExprStmt target_18, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtrylevel
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsave_trylevel_597
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_4)
		and target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_5(Variable vsuppress_errthrow, ExprStmt target_19, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsuppress_errthrow
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_5)
		and target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_6(Variable vexpected_631, Variable vactual_635, BlockStmt target_8, NotExpr target_6) {
		target_6.getOperand().(FunctionCall).getTarget().hasName("pattern_match")
		and target_6.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpected_631
		and target_6.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vactual_635
		and target_6.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_6.getParent().(IfStmt).getThen()=target_8
}

predicate func_7(Variable vactual_635, BlockStmt target_20, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vactual_635
		and target_7.getAnOperand().(Literal).getValue()="0"
		and target_7.getParent().(IfStmt).getThen()=target_20
}

predicate func_8(Variable vexpected_631, Variable vexpected_str_632, Variable verror_found_633, BlockStmt target_8) {
		target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_found_633
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_8.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexpected_str_632
		and target_8.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vexpected_631
}

predicate func_9(Variable vbuf_630, Variable vexpected_631, Variable vtv_647, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexpected_631
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tv_get_string_buf_chk")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtv_647
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_630
}

predicate func_10(EqualityOperation target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="lv_len"
		and target_10.getAnOperand().(Literal).getValue()="2"
}

predicate func_11(Variable vexpected_631, Variable vexpected_str_632, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexpected_str_632
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vexpected_631
}

predicate func_12(Variable vexpected_str_632, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("fill_assert_error")
		and target_12.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vexpected_str_632
}

predicate func_13(Variable verror_found_633, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_found_633
		and target_13.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_14(Variable verror_found_633, LogicalAndExpr target_14) {
		target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=verror_found_633
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="v_type"
		and target_14.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="v_type"
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
}

predicate func_15(Variable vactual_635, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="v_string"
		and target_15.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="vval"
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vactual_635
}

predicate func_16(Variable vbuf_630, Variable vexpected_631, Variable vtv_647, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexpected_631
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tv_get_string_buf_chk")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtv_647
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_630
}

predicate func_17(Variable vexpected_631, Variable vactual_635, NotExpr target_17) {
		target_17.getOperand().(FunctionCall).getTarget().hasName("pattern_match")
		and target_17.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpected_631
		and target_17.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vactual_635
		and target_17.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_18(Variable vsave_trylevel_597, Variable vtrylevel, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtrylevel
		and target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsave_trylevel_597
}

predicate func_19(Variable vsuppress_errthrow, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsuppress_errthrow
		and target_19.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_20(Variable vbuf_630, Variable vexpected_631, Variable vtv_647, BlockStmt target_20) {
		target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtv_647
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="li_tv"
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="lv_last"
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mat"
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexpected_631
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tv_get_string_buf_chk")
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtv_647
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_630
}

from Function func, Variable vsave_trylevel_597, Variable vtrylevel, Variable vsuppress_errthrow, Variable vbuf_630, Variable vexpected_631, Variable vexpected_str_632, Variable verror_found_633, Variable vactual_635, Variable vtv_647, NotExpr target_6, EqualityOperation target_7, BlockStmt target_8, ExprStmt target_9, EqualityOperation target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, LogicalAndExpr target_14, ExprStmt target_15, ExprStmt target_16, NotExpr target_17, ExprStmt target_18, ExprStmt target_19, BlockStmt target_20
where
not func_0(vexpected_631, target_8, target_9, target_6)
and not func_1(target_6, func)
and not func_2(vbuf_630, vexpected_631, vexpected_str_632, verror_found_633, vactual_635, vtv_647, target_10, target_9, target_11, target_12, target_13, target_14, target_7, target_15)
and not func_4(vsave_trylevel_597, vtrylevel, target_18, func)
and not func_5(vsuppress_errthrow, target_19, func)
and func_6(vexpected_631, vactual_635, target_8, target_6)
and func_7(vactual_635, target_20, target_7)
and func_8(vexpected_631, vexpected_str_632, verror_found_633, target_8)
and func_9(vbuf_630, vexpected_631, vtv_647, target_9)
and func_10(target_10)
and func_11(vexpected_631, vexpected_str_632, target_11)
and func_12(vexpected_str_632, target_12)
and func_13(verror_found_633, target_13)
and func_14(verror_found_633, target_14)
and func_15(vactual_635, target_15)
and func_16(vbuf_630, vexpected_631, vtv_647, target_16)
and func_17(vexpected_631, vactual_635, target_17)
and func_18(vsave_trylevel_597, vtrylevel, target_18)
and func_19(vsuppress_errthrow, target_19)
and func_20(vbuf_630, vexpected_631, vtv_647, target_20)
and vsave_trylevel_597.getType().hasName("int")
and vtrylevel.getType().hasName("int")
and vsuppress_errthrow.getType().hasName("int")
and vbuf_630.getType().hasName("char_u[65]")
and vexpected_631.getType().hasName("char_u *")
and vexpected_str_632.getType().hasName("char_u *")
and verror_found_633.getType().hasName("int")
and vactual_635.getType().hasName("char_u *")
and vtv_647.getType().hasName("typval_T *")
and vsave_trylevel_597.getParentScope+() = func
and not vtrylevel.getParentScope+() = func
and not vsuppress_errthrow.getParentScope+() = func
and vbuf_630.getParentScope+() = func
and vexpected_631.getParentScope+() = func
and vexpected_str_632.getParentScope+() = func
and verror_found_633.getParentScope+() = func
and vactual_635.getParentScope+() = func
and vtv_647.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
