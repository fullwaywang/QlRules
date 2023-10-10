/**
 * @name linux-ff05d4b45dd89b922578dac497dcabf57cf771c6-ieee802_11_parse_elems_full
 * @id cpp/linux/ff05d4b45dd89b922578dac497dcabf57cf771c6/ieee802_11_parse_elems_full
 * @description linux-ff05d4b45dd89b922578dac497dcabf57cf771c6-ieee802_11_parse_elems_full CVE-2022-42719
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable velems_1505) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="552"
		and target_0.getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=velems_1505)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof PointerFieldAccess
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_1)
}

predicate func_2(Variable velems_1505) {
	exists(AddExpr target_2 |
		target_2.getAnOperand().(SizeofExprOperator).getValue()="568"
		and target_2.getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=velems_1505
		and target_2.getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("kzalloc")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getValue()="2592"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="544"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="32"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="512"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048")
}

predicate func_3(Variable velems_1505) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(PointerFieldAccess).getTarget().getName()="scratch_len"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velems_1505
		and target_3.getRValue().(VariableAccess).getType().hasName("size_t"))
}

predicate func_4(Variable velems_1505) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="scratch_pos"
		and target_4.getQualifier().(VariableAccess).getTarget()=velems_1505)
}

predicate func_5(Variable velems_1505) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="scratch"
		and target_5.getQualifier().(VariableAccess).getTarget()=velems_1505)
}

predicate func_6(Variable velems_1505, Variable vnontransmitted_profile_1507, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnontransmitted_profile_1507
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="scratch_pos"
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velems_1505
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_6))
}

predicate func_7(Variable velems_1505, Variable vnontransmitted_profile_len_1508, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="scratch_pos"
		and target_7.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velems_1505
		and target_7.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vnontransmitted_profile_len_1508
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_7))
}

predicate func_8(Variable velems_1505, Variable vnontransmitted_profile_len_1508, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="scratch_len"
		and target_8.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velems_1505
		and target_8.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vnontransmitted_profile_len_1508
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_8))
}

predicate func_9(Parameter vparams_1503) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="len"
		and target_9.getQualifier().(VariableAccess).getTarget()=vparams_1503)
}

predicate func_10(Parameter vparams_1503, Variable velems_1505, Variable vnontransmitted_profile_1507, Variable vnontransmitted_profile_len_1508) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnontransmitted_profile_len_1508
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ieee802_11_find_bssid_profile")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="start"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_1503
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="len"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_1503
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=velems_1505
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="bss"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_1503
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vnontransmitted_profile_1507
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vnontransmitted_profile_1507)
}

predicate func_11(Variable vnon_inherit_1506, Variable vnontransmitted_profile_1507, Variable vnontransmitted_profile_len_1508) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnon_inherit_1506
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cfg80211_find_ext_elem")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnontransmitted_profile_1507
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnontransmitted_profile_len_1508
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vnontransmitted_profile_1507)
}

predicate func_13(Function func) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("kmalloc")
		and target_13.getArgument(0) instanceof PointerFieldAccess
		and target_13.getArgument(1).(BitwiseOrExpr).getValue()="2592"
		and target_13.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="544"
		and target_13.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="32"
		and target_13.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="512"
		and target_13.getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Variable vnontransmitted_profile_1507, Function func) {
	exists(IfStmt target_14 |
		target_14.getCondition().(VariableAccess).getTarget()=vnontransmitted_profile_1507
		and target_14.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_14.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14)
}

predicate func_15(Variable vnontransmitted_profile_1507) {
	exists(FunctionCall target_15 |
		target_15.getTarget().hasName("kfree")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vnontransmitted_profile_1507)
}

predicate func_16(Variable velems_1505) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="total_len"
		and target_16.getQualifier().(VariableAccess).getTarget()=velems_1505)
}

predicate func_17(Parameter vparams_1503, Variable velems_1505, Variable vnontransmitted_profile_1507) {
	exists(FunctionCall target_17 |
		target_17.getTarget().hasName("ieee802_11_find_bssid_profile")
		and target_17.getArgument(0).(PointerFieldAccess).getTarget().getName()="start"
		and target_17.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_1503
		and target_17.getArgument(1).(PointerFieldAccess).getTarget().getName()="len"
		and target_17.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_1503
		and target_17.getArgument(2).(VariableAccess).getTarget()=velems_1505
		and target_17.getArgument(3).(PointerFieldAccess).getTarget().getName()="bss"
		and target_17.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_1503
		and target_17.getArgument(4).(VariableAccess).getTarget()=vnontransmitted_profile_1507)
}

predicate func_18(Parameter vparams_1503, Variable velems_1505, Variable vnon_inherit_1506) {
	exists(FunctionCall target_18 |
		target_18.getTarget().hasName("_ieee802_11_parse_elems_full")
		and target_18.getArgument(0).(VariableAccess).getTarget()=vparams_1503
		and target_18.getArgument(1).(VariableAccess).getTarget()=velems_1505
		and target_18.getArgument(2).(VariableAccess).getTarget()=vnon_inherit_1506)
}

predicate func_19(Variable vnontransmitted_profile_1507, Variable vnontransmitted_profile_len_1508) {
	exists(FunctionCall target_19 |
		target_19.getTarget().hasName("cfg80211_find_ext_elem")
		and target_19.getArgument(1).(VariableAccess).getTarget()=vnontransmitted_profile_1507
		and target_19.getArgument(2).(VariableAccess).getTarget()=vnontransmitted_profile_len_1508)
}

from Function func, Parameter vparams_1503, Variable velems_1505, Variable vnon_inherit_1506, Variable vnontransmitted_profile_1507, Variable vnontransmitted_profile_len_1508
where
func_0(velems_1505)
and not func_1(func)
and not func_2(velems_1505)
and not func_3(velems_1505)
and not func_4(velems_1505)
and not func_5(velems_1505)
and not func_6(velems_1505, vnontransmitted_profile_1507, func)
and not func_7(velems_1505, vnontransmitted_profile_len_1508, func)
and not func_8(velems_1505, vnontransmitted_profile_len_1508, func)
and func_9(vparams_1503)
and func_10(vparams_1503, velems_1505, vnontransmitted_profile_1507, vnontransmitted_profile_len_1508)
and func_11(vnon_inherit_1506, vnontransmitted_profile_1507, vnontransmitted_profile_len_1508)
and func_13(func)
and func_14(vnontransmitted_profile_1507, func)
and func_15(vnontransmitted_profile_1507)
and vparams_1503.getType().hasName("ieee80211_elems_parse_params *")
and velems_1505.getType().hasName("ieee802_11_elems *")
and func_16(velems_1505)
and func_17(vparams_1503, velems_1505, vnontransmitted_profile_1507)
and func_18(vparams_1503, velems_1505, vnon_inherit_1506)
and vnon_inherit_1506.getType().hasName("const element *")
and vnontransmitted_profile_1507.getType().hasName("u8 *")
and vnontransmitted_profile_len_1508.getType().hasName("int")
and func_19(vnontransmitted_profile_1507, vnontransmitted_profile_len_1508)
and vparams_1503.getParentScope+() = func
and velems_1505.getParentScope+() = func
and vnon_inherit_1506.getParentScope+() = func
and vnontransmitted_profile_1507.getParentScope+() = func
and vnontransmitted_profile_len_1508.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
