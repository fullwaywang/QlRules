/**
 * @name openssl-56fb454d281a023b3f950d969693553d3f3ceea1-ec_mul_consttime
 * @id cpp/openssl/56fb454d281a023b3f950d969693553d3f3ceea1/ec-mul-consttime
 * @description openssl-56fb454d281a023b3f950d969693553d3f3ceea1-crypto/ec/ec_mult.c-ec_mul_consttime CVE-2018-0735
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vgroup_top_139, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="2"
		and target_0.getParent().(AddExpr).getParent().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vgroup_top_139
}

predicate func_1(Variable vgroup_top_139, Literal target_1) {
		target_1.getValue()="1"
		and not target_1.getValue()="2"
		and target_1.getParent().(AddExpr).getParent().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vgroup_top_139
}

predicate func_2(Variable vgroup_top_139, Literal target_2) {
		target_2.getValue()="1"
		and not target_2.getValue()="2"
		and target_2.getParent().(AddExpr).getParent().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vgroup_top_139
}

predicate func_3(Function func) {
	exists(ReturnStmt target_3 |
		target_3.toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_3))
}

predicate func_4(Parameter vscalar_136, Variable vk_141, Function func, IfStmt target_4) {
		target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vk_141
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vscalar_136
		and target_4.getThen().(GotoStmt).toString() = "goto ..."
		and target_4.getThen().(GotoStmt).getName() ="err"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Variable vk_141, Function func, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("BN_set_flags")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vk_141
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Parameter vctx_137, Variable vcardinality_bits_139, Variable vk_141, Variable vcardinality_143, Function func, IfStmt target_6) {
		target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vk_141
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcardinality_bits_139
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("BN_is_negative")
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vk_141
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_nnmod")
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vk_141
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vk_141
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcardinality_143
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vctx_137
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).getName() ="err"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Variable vk_141, Variable vlambda_142, Variable vcardinality_143, Function func, IfStmt target_7) {
		target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlambda_142
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vk_141
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcardinality_143
		and target_7.getThen().(GotoStmt).toString() = "goto ..."
		and target_7.getThen().(GotoStmt).getName() ="err"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vlambda_142, Function func, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("BN_set_flags")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlambda_142
		and target_8.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(Variable vk_141, Variable vlambda_142, Variable vcardinality_143, Function func, IfStmt target_9) {
		target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vk_141
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlambda_142
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcardinality_143
		and target_9.getThen().(GotoStmt).toString() = "goto ..."
		and target_9.getThen().(GotoStmt).getName() ="err"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

predicate func_10(Variable vcardinality_bits_139, Variable vkbit_139, Variable vlambda_142, Function func, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vkbit_139
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_is_bit_set")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlambda_142
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcardinality_bits_139
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Parameter vgroup_135, Variable vgroup_top_139, Function func, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vgroup_top_139
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bn_get_top")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="field"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_135
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

predicate func_12(Parameter vr_135, Variable vgroup_top_139, Function func, IfStmt target_12) {
		target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("bn_wexpand")
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("bn_wexpand")
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="X"
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vgroup_top_139
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("bn_wexpand")
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="Y"
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_135
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vgroup_top_139
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("bn_wexpand")
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="Z"
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_135
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vgroup_top_139
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getThen().(GotoStmt).toString() = "goto ..."
		and target_12.getThen().(GotoStmt).getName() ="err"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12
}

predicate func_13(Parameter vgroup_135, Parameter vctx_137, Variable vs_140, Function func, IfStmt target_13) {
		target_13.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ec_point_blind_coordinates")
		and target_13.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup_135
		and target_13.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_140
		and target_13.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vctx_137
		and target_13.getThen().(GotoStmt).toString() = "goto ..."
		and target_13.getThen().(GotoStmt).getName() ="err"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13
}

predicate func_14(Parameter vr_135, Variable vs_140, Function func, IfStmt target_14) {
		target_14.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("EC_POINT_copy")
		and target_14.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_135
		and target_14.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_140
		and target_14.getThen().(GotoStmt).toString() = "goto ..."
		and target_14.getThen().(GotoStmt).getName() ="err"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Parameter vr_135, Function func, DoStmt target_15) {
		target_15.getCondition().(Literal).getValue()="0"
		and target_15.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_set_flags")
		and target_15.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="X"
		and target_15.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_135
		and target_15.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_15.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_set_flags")
		and target_15.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="Y"
		and target_15.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_135
		and target_15.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_15.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_set_flags")
		and target_15.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="Z"
		and target_15.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_135
		and target_15.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_15
}

predicate func_16(Parameter vgroup_135, Parameter vctx_137, Variable vs_140, Function func, IfStmt target_16) {
		target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("EC_POINT_dbl")
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup_135
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_140
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_140
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vctx_137
		and target_16.getThen().(GotoStmt).toString() = "goto ..."
		and target_16.getThen().(GotoStmt).getName() ="err"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_16
}

predicate func_17(Variable vpbit_139, Function func, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpbit_139
		and target_17.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_17
}

predicate func_18(Parameter vgroup_135, Parameter vr_135, Parameter vctx_137, Variable vi_139, Variable vcardinality_bits_139, Variable vgroup_top_139, Variable vkbit_139, Variable vpbit_139, Variable vZ_is_one_139, Variable vs_140, Variable vk_141, Function func, ForStmt target_18) {
		target_18.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_139
		and target_18.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vcardinality_bits_139
		and target_18.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_18.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_139
		and target_18.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_18.getUpdate().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vi_139
		and target_18.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vkbit_139
		and target_18.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseXorExpr).getLeftOperand().(FunctionCall).getTarget().hasName("BN_is_bit_set")
		and target_18.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseXorExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vk_141
		and target_18.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseXorExpr).getLeftOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vi_139
		and target_18.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseXorExpr).getRightOperand().(VariableAccess).getTarget()=vpbit_139
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_consttime_swap")
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkbit_139
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="X"
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="X"
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vgroup_top_139
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_consttime_swap")
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkbit_139
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="Y"
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="Y"
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vgroup_top_139
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_consttime_swap")
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkbit_139
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="Z"
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="Z"
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vgroup_top_139
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vZ_is_one_139
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignXorExpr).getLValue().(PointerFieldAccess).getTarget().getName()="Z_is_one"
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignXorExpr).getRValue().(VariableAccess).getTarget()=vZ_is_one_139
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignXorExpr).getLValue().(PointerFieldAccess).getTarget().getName()="Z_is_one"
		and target_18.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignXorExpr).getRValue().(VariableAccess).getTarget()=vZ_is_one_139
		and target_18.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("EC_POINT_add")
		and target_18.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup_135
		and target_18.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_140
		and target_18.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vr_135
		and target_18.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vs_140
		and target_18.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vctx_137
		and target_18.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_18.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(GotoStmt).getName() ="err"
		and target_18.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("EC_POINT_dbl")
		and target_18.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup_135
		and target_18.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vr_135
		and target_18.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vr_135
		and target_18.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vctx_137
		and target_18.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_18.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(GotoStmt).getName() ="err"
		and target_18.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignXorExpr).getLValue().(VariableAccess).getTarget()=vpbit_139
		and target_18.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignXorExpr).getRValue().(VariableAccess).getTarget()=vkbit_139
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18
}

predicate func_19(Parameter vr_135, Variable vgroup_top_139, Variable vpbit_139, Variable vZ_is_one_139, Variable vs_140, Function func, DoStmt target_19) {
		target_19.getCondition().(Literal).getValue()="0"
		and target_19.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_consttime_swap")
		and target_19.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpbit_139
		and target_19.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="X"
		and target_19.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_135
		and target_19.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="X"
		and target_19.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_140
		and target_19.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vgroup_top_139
		and target_19.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_consttime_swap")
		and target_19.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpbit_139
		and target_19.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="Y"
		and target_19.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_135
		and target_19.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="Y"
		and target_19.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_140
		and target_19.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vgroup_top_139
		and target_19.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_consttime_swap")
		and target_19.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpbit_139
		and target_19.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="Z"
		and target_19.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_135
		and target_19.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="Z"
		and target_19.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_140
		and target_19.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vgroup_top_139
		and target_19.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vZ_is_one_139
		and target_19.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(BitwiseXorExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="Z_is_one"
		and target_19.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(BitwiseXorExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="Z_is_one"
		and target_19.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vpbit_139
		and target_19.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignXorExpr).getLValue().(PointerFieldAccess).getTarget().getName()="Z_is_one"
		and target_19.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignXorExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_135
		and target_19.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignXorExpr).getRValue().(VariableAccess).getTarget()=vZ_is_one_139
		and target_19.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignXorExpr).getLValue().(PointerFieldAccess).getTarget().getName()="Z_is_one"
		and target_19.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignXorExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_140
		and target_19.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignXorExpr).getRValue().(VariableAccess).getTarget()=vZ_is_one_139
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_19
}

predicate func_20(Variable vret_145, Function func, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_145
		and target_20.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_20
}

predicate func_21(Variable vs_140, Function func, ExprStmt target_21) {
		target_21.getExpr().(FunctionCall).getTarget().hasName("EC_POINT_free")
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_140
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_21
}

predicate func_22(Parameter vctx_137, Function func, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("BN_CTX_end")
		and target_22.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_137
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_22
}

predicate func_23(Variable vnew_ctx_144, Function func, ExprStmt target_23) {
		target_23.getExpr().(FunctionCall).getTarget().hasName("BN_CTX_free")
		and target_23.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnew_ctx_144
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_23
}

predicate func_24(Variable vret_145, Function func, ReturnStmt target_24) {
		target_24.getExpr().(VariableAccess).getTarget()=vret_145
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_24
}

predicate func_25(LogicalOrExpr target_27, Function func, GotoStmt target_25) {
		target_25.toString() = "goto ..."
		and target_25.getName() ="err"
		and target_25.getParent().(IfStmt).getCondition()=target_27
		and target_25.getEnclosingFunction() = func
}

predicate func_26(Function func, LabelStmt target_26) {
		target_26.toString() = "label ...:"
		and target_26.getName() ="err"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_26
}

predicate func_27(Variable vgroup_top_139, Variable vk_141, Variable vlambda_142, LogicalOrExpr target_27) {
		target_27.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("bn_wexpand")
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vk_141
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vgroup_top_139
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand() instanceof Literal
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("bn_wexpand")
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlambda_142
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vgroup_top_139
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand() instanceof Literal
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vgroup_135, Parameter vr_135, Parameter vscalar_136, Parameter vctx_137, Variable vi_139, Variable vcardinality_bits_139, Variable vgroup_top_139, Variable vkbit_139, Variable vpbit_139, Variable vZ_is_one_139, Variable vs_140, Variable vk_141, Variable vlambda_142, Variable vcardinality_143, Variable vnew_ctx_144, Variable vret_145, Literal target_0, Literal target_1, Literal target_2, IfStmt target_4, ExprStmt target_5, IfStmt target_6, IfStmt target_7, ExprStmt target_8, IfStmt target_9, ExprStmt target_10, ExprStmt target_11, IfStmt target_12, IfStmt target_13, IfStmt target_14, DoStmt target_15, IfStmt target_16, ExprStmt target_17, ForStmt target_18, DoStmt target_19, ExprStmt target_20, ExprStmt target_21, ExprStmt target_22, ExprStmt target_23, ReturnStmt target_24, GotoStmt target_25, LabelStmt target_26, LogicalOrExpr target_27
where
func_0(vgroup_top_139, target_0)
and func_1(vgroup_top_139, target_1)
and func_2(vgroup_top_139, target_2)
and not func_3(func)
and func_4(vscalar_136, vk_141, func, target_4)
and func_5(vk_141, func, target_5)
and func_6(vctx_137, vcardinality_bits_139, vk_141, vcardinality_143, func, target_6)
and func_7(vk_141, vlambda_142, vcardinality_143, func, target_7)
and func_8(vlambda_142, func, target_8)
and func_9(vk_141, vlambda_142, vcardinality_143, func, target_9)
and func_10(vcardinality_bits_139, vkbit_139, vlambda_142, func, target_10)
and func_11(vgroup_135, vgroup_top_139, func, target_11)
and func_12(vr_135, vgroup_top_139, func, target_12)
and func_13(vgroup_135, vctx_137, vs_140, func, target_13)
and func_14(vr_135, vs_140, func, target_14)
and func_15(vr_135, func, target_15)
and func_16(vgroup_135, vctx_137, vs_140, func, target_16)
and func_17(vpbit_139, func, target_17)
and func_18(vgroup_135, vr_135, vctx_137, vi_139, vcardinality_bits_139, vgroup_top_139, vkbit_139, vpbit_139, vZ_is_one_139, vs_140, vk_141, func, target_18)
and func_19(vr_135, vgroup_top_139, vpbit_139, vZ_is_one_139, vs_140, func, target_19)
and func_20(vret_145, func, target_20)
and func_21(vs_140, func, target_21)
and func_22(vctx_137, func, target_22)
and func_23(vnew_ctx_144, func, target_23)
and func_24(vret_145, func, target_24)
and func_25(target_27, func, target_25)
and func_26(func, target_26)
and func_27(vgroup_top_139, vk_141, vlambda_142, target_27)
and vgroup_135.getType().hasName("const EC_GROUP *")
and vr_135.getType().hasName("EC_POINT *")
and vscalar_136.getType().hasName("const BIGNUM *")
and vctx_137.getType().hasName("BN_CTX *")
and vi_139.getType().hasName("int")
and vcardinality_bits_139.getType().hasName("int")
and vgroup_top_139.getType().hasName("int")
and vkbit_139.getType().hasName("int")
and vpbit_139.getType().hasName("int")
and vZ_is_one_139.getType().hasName("int")
and vs_140.getType().hasName("EC_POINT *")
and vk_141.getType().hasName("BIGNUM *")
and vlambda_142.getType().hasName("BIGNUM *")
and vcardinality_143.getType().hasName("BIGNUM *")
and vnew_ctx_144.getType().hasName("BN_CTX *")
and vret_145.getType().hasName("int")
and vgroup_135.getParentScope+() = func
and vr_135.getParentScope+() = func
and vscalar_136.getParentScope+() = func
and vctx_137.getParentScope+() = func
and vi_139.getParentScope+() = func
and vcardinality_bits_139.getParentScope+() = func
and vgroup_top_139.getParentScope+() = func
and vkbit_139.getParentScope+() = func
and vpbit_139.getParentScope+() = func
and vZ_is_one_139.getParentScope+() = func
and vs_140.getParentScope+() = func
and vk_141.getParentScope+() = func
and vlambda_142.getParentScope+() = func
and vcardinality_143.getParentScope+() = func
and vnew_ctx_144.getParentScope+() = func
and vret_145.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
