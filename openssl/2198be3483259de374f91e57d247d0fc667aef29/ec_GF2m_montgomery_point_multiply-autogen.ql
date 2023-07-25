/**
 * @name openssl-2198be3483259de374f91e57d247d0fc667aef29-ec_GF2m_montgomery_point_multiply
 * @id cpp/openssl/2198be3483259de374f91e57d247d0fc667aef29/ec-GF2m-montgomery-point-multiply
 * @description openssl-2198be3483259de374f91e57d247d0fc667aef29-ec_GF2m_montgomery_point_multiply CVE-2014-0076
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vgroup_215, Variable vx1_218, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="top"
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="field"
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_215
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="dmax"
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx1_218
		and target_0.getExpr().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vx1_218
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("bn_expand2")
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vx1_218
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="top"
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="field"
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_215
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vgroup_215, Variable vz1_218, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="top"
		and target_1.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="field"
		and target_1.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_215
		and target_1.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="dmax"
		and target_1.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vz1_218
		and target_1.getExpr().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vz1_218
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("bn_expand2")
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vz1_218
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="top"
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="field"
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_215
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vgroup_215, Variable vx2_218, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="top"
		and target_2.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="field"
		and target_2.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_215
		and target_2.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="dmax"
		and target_2.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx2_218
		and target_2.getExpr().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vx2_218
		and target_2.getExpr().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("bn_expand2")
		and target_2.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vx2_218
		and target_2.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="top"
		and target_2.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="field"
		and target_2.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_215
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vgroup_215, Variable vz2_218, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="top"
		and target_3.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="field"
		and target_3.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_215
		and target_3.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="dmax"
		and target_3.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vz2_218
		and target_3.getExpr().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vz2_218
		and target_3.getExpr().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("bn_expand2")
		and target_3.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vz2_218
		and target_3.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="top"
		and target_3.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="field"
		and target_3.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_215
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_3))
}

predicate func_4(Parameter vgroup_215, Variable vx1_218, Variable vx2_218) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("BN_consttime_swap")
		and target_4.getExpr().(FunctionCall).getArgument(0) instanceof BitwiseAndExpr
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vx1_218
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vx2_218
		and target_4.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="top"
		and target_4.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="field"
		and target_4.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_215)
}

predicate func_5(Parameter vgroup_215, Variable vz1_218, Variable vz2_218, Variable vmask_220, Variable vword_220) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("BN_consttime_swap")
		and target_5.getExpr().(FunctionCall).getArgument(0).(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vword_220
		and target_5.getExpr().(FunctionCall).getArgument(0).(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vmask_220
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vz1_218
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vz2_218
		and target_5.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="top"
		and target_5.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="field"
		and target_5.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_215)
}

predicate func_9(Parameter vpoint_216) {
	exists(AddressOfExpr target_9 |
		target_9.getOperand().(PointerFieldAccess).getTarget().getName()="X"
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpoint_216
		and target_9.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall)
}

predicate func_10(Parameter vgroup_215, Parameter vpoint_216, Parameter vctx_216, Variable vx1_218, Variable vx2_218, Variable vz1_218, Variable vz2_218, Variable vmask_220, Variable vword_220) {
	exists(IfStmt target_10 |
		target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("gf2m_Madd")
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup_215
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="X"
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpoint_216
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vx2_218
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vz2_218
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vx1_218
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vz1_218
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vctx_216
		and target_10.getThen().(GotoStmt).toString() = "goto ..."
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vword_220
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vmask_220)
}

predicate func_11(Parameter vgroup_215, Parameter vctx_216, Variable vx1_218, Variable vz1_218, Variable vmask_220, Variable vword_220) {
	exists(IfStmt target_11 |
		target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("gf2m_Mdouble")
		and target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup_215
		and target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vx1_218
		and target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vz1_218
		and target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vctx_216
		and target_11.getThen().(GotoStmt).toString() = "goto ..."
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vword_220
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vmask_220)
}

predicate func_20(Parameter vgroup_215, Parameter vctx_216, Variable vx1_218, Variable vx2_218, Variable vz1_218, Variable vz2_218) {
	exists(IfStmt target_20 |
		target_20.getCondition() instanceof BitwiseAndExpr
		and target_20.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("gf2m_Madd")
		and target_20.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup_215
		and target_20.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof AddressOfExpr
		and target_20.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vx1_218
		and target_20.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vz1_218
		and target_20.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vx2_218
		and target_20.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vz2_218
		and target_20.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vctx_216
		and target_20.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_20.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("gf2m_Mdouble")
		and target_20.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup_215
		and target_20.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vx2_218
		and target_20.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vz2_218
		and target_20.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vctx_216
		and target_20.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_20.getElse().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_20.getElse().(BlockStmt).getStmt(1) instanceof IfStmt)
}

predicate func_23(Parameter vgroup_215, Parameter vr_215) {
	exists(FunctionCall target_23 |
		target_23.getTarget().hasName("EC_POINT_set_to_infinity")
		and target_23.getArgument(0).(VariableAccess).getTarget()=vgroup_215
		and target_23.getArgument(1).(VariableAccess).getTarget()=vr_215)
}

predicate func_24(Parameter vgroup_215, Variable vx2_218) {
	exists(AddressOfExpr target_24 |
		target_24.getOperand().(PointerFieldAccess).getTarget().getName()="b"
		and target_24.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_215
		and target_24.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_GF2m_add")
		and target_24.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vx2_218
		and target_24.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vx2_218)
}

predicate func_25(Parameter vgroup_215, Parameter vctx_216, Variable vx1_218, Variable vz1_218) {
	exists(NotExpr target_25 |
		target_25.getOperand().(FunctionCall).getTarget().hasName("gf2m_Mdouble")
		and target_25.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup_215
		and target_25.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vx1_218
		and target_25.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vz1_218
		and target_25.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vctx_216
		and target_25.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_26(Parameter vctx_216, Variable vx1_218) {
	exists(AssignExpr target_26 |
		target_26.getLValue().(VariableAccess).getTarget()=vx1_218
		and target_26.getRValue().(FunctionCall).getTarget().hasName("BN_CTX_get")
		and target_26.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_216)
}

predicate func_27(Parameter vgroup_215, Parameter vctx_216, Variable vx1_218, Variable vz2_218) {
	exists(NotExpr target_27 |
		target_27.getOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="field_sqr"
		and target_27.getOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="meth"
		and target_27.getOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_215
		and target_27.getOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vgroup_215
		and target_27.getOperand().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vz2_218
		and target_27.getOperand().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vx1_218
		and target_27.getOperand().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vctx_216
		and target_27.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_29(Parameter vr_215, Variable vx2_218) {
	exists(AssignExpr target_29 |
		target_29.getLValue().(VariableAccess).getTarget()=vx2_218
		and target_29.getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="X"
		and target_29.getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_215)
}

predicate func_30(Parameter vgroup_215, Variable vx2_218) {
	exists(NotExpr target_30 |
		target_30.getOperand().(FunctionCall).getTarget().hasName("BN_GF2m_add")
		and target_30.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vx2_218
		and target_30.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vx2_218
		and target_30.getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="b"
		and target_30.getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_215
		and target_30.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_31(Parameter vgroup_215, Parameter vpoint_216, Parameter vctx_216, Variable vx1_218, Variable vx2_218, Variable vz1_218, Variable vz2_218) {
	exists(NotExpr target_31 |
		target_31.getOperand().(FunctionCall).getTarget().hasName("gf2m_Madd")
		and target_31.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup_215
		and target_31.getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="X"
		and target_31.getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpoint_216
		and target_31.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vx2_218
		and target_31.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vz2_218
		and target_31.getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vx1_218
		and target_31.getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vz1_218
		and target_31.getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vctx_216
		and target_31.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_32(Variable vz1_218) {
	exists(EqualityOperation target_32 |
		target_32.getAnOperand().(VariableAccess).getTarget()=vz1_218
		and target_32.getAnOperand().(Literal).getValue()="0"
		and target_32.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_33(Variable vz1_218) {
	exists(NotExpr target_33 |
		target_33.getOperand().(FunctionCall).getTarget().hasName("BN_set_word")
		and target_33.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vz1_218
		and target_33.getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_33.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_35(Parameter vr_215, Variable vz2_218) {
	exists(AssignExpr target_35 |
		target_35.getLValue().(VariableAccess).getTarget()=vz2_218
		and target_35.getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="Y"
		and target_35.getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_215)
}

predicate func_37(Variable vmask_220) {
	exists(WhileStmt target_37 |
		target_37.getCondition().(VariableAccess).getTarget()=vmask_220
		and target_37.getStmt().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_37.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignRShiftExpr).getLValue().(VariableAccess).getTarget()=vmask_220
		and target_37.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignRShiftExpr).getRValue().(Literal).getValue()="1")
}

predicate func_38(Variable vmask_220) {
	exists(AssignRShiftExpr target_38 |
		target_38.getLValue().(VariableAccess).getTarget()=vmask_220
		and target_38.getRValue().(Literal).getValue()="1")
}

predicate func_39(Parameter vscalar_215, Variable vi_219, Variable vword_220) {
	exists(AssignExpr target_39 |
		target_39.getLValue().(VariableAccess).getTarget()=vword_220
		and target_39.getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d"
		and target_39.getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscalar_215
		and target_39.getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_219)
}

from Function func, Parameter vgroup_215, Parameter vr_215, Parameter vscalar_215, Parameter vpoint_216, Parameter vctx_216, Variable vx1_218, Variable vx2_218, Variable vz1_218, Variable vz2_218, Variable vi_219, Variable vmask_220, Variable vword_220
where
not func_0(vgroup_215, vx1_218, func)
and not func_1(vgroup_215, vz1_218, func)
and not func_2(vgroup_215, vx2_218, func)
and not func_3(vgroup_215, vz2_218, func)
and not func_4(vgroup_215, vx1_218, vx2_218)
and not func_5(vgroup_215, vz1_218, vz2_218, vmask_220, vword_220)
and func_9(vpoint_216)
and func_10(vgroup_215, vpoint_216, vctx_216, vx1_218, vx2_218, vz1_218, vz2_218, vmask_220, vword_220)
and func_11(vgroup_215, vctx_216, vx1_218, vz1_218, vmask_220, vword_220)
and func_20(vgroup_215, vctx_216, vx1_218, vx2_218, vz1_218, vz2_218)
and vgroup_215.getType().hasName("const EC_GROUP *")
and func_23(vgroup_215, vr_215)
and func_24(vgroup_215, vx2_218)
and func_25(vgroup_215, vctx_216, vx1_218, vz1_218)
and vr_215.getType().hasName("EC_POINT *")
and vpoint_216.getType().hasName("const EC_POINT *")
and vctx_216.getType().hasName("BN_CTX *")
and vx1_218.getType().hasName("BIGNUM *")
and func_26(vctx_216, vx1_218)
and func_27(vgroup_215, vctx_216, vx1_218, vz2_218)
and vx2_218.getType().hasName("BIGNUM *")
and func_29(vr_215, vx2_218)
and func_30(vgroup_215, vx2_218)
and func_31(vgroup_215, vpoint_216, vctx_216, vx1_218, vx2_218, vz1_218, vz2_218)
and vz1_218.getType().hasName("BIGNUM *")
and func_32(vz1_218)
and func_33(vz1_218)
and vz2_218.getType().hasName("BIGNUM *")
and func_35(vr_215, vz2_218)
and vmask_220.getType().hasName("unsigned long")
and func_37(vmask_220)
and func_38(vmask_220)
and vword_220.getType().hasName("unsigned long")
and func_39(vscalar_215, vi_219, vword_220)
and vgroup_215.getParentScope+() = func
and vr_215.getParentScope+() = func
and vscalar_215.getParentScope+() = func
and vpoint_216.getParentScope+() = func
and vctx_216.getParentScope+() = func
and vx1_218.getParentScope+() = func
and vx2_218.getParentScope+() = func
and vz1_218.getParentScope+() = func
and vz2_218.getParentScope+() = func
and vi_219.getParentScope+() = func
and vmask_220.getParentScope+() = func
and vword_220.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
