/**
 * @name freeradius-4b059296e14b6ab75dc17163077490528a819806-data2vp_extended
 * @id cpp/freeradius/4b059296e14b6ab75dc17163077490528a819806/data2vp-extended
 * @description freeradius-4b059296e14b6ab75dc17163077490528a819806-src/lib/radius.c-data2vp_extended CVE-2017-10984
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vattrlen_3152, Variable vfraglen_3156, VariableAccess target_0) {
		target_0.getTarget()=vfraglen_3156
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrlen_3152
		and target_0.getParent().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_1(Parameter vdata_3151, Parameter vattrlen_3152, Variable vfrag_3158, ExprStmt target_90, ExprStmt target_91, RelationalOperation target_92, VariableAccess target_1) {
		target_1.getTarget()=vfrag_3158
		and target_1.getParent().(AssignExpr).getLValue() = target_1
		and target_1.getParent().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_3151
		and target_1.getParent().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vattrlen_3152
		and target_1.getParent().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_90.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_91.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getParent().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getLocation().isBefore(target_92.getLesserOperand().(VariableAccess).getLocation())
}

predicate func_2(Variable vfrag_3158, Variable vend_3158, ExprStmt target_93, LogicalOrExpr target_94, ExprStmt target_90, VariableAccess target_2) {
		target_2.getTarget()=vfrag_3158
		and target_2.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getTarget()=vend_3158
		and target_93.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getLocation())
		and target_2.getLocation().isBefore(target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_90.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getLocation())
}

/*predicate func_3(Variable vfrag_3158, RelationalOperation target_92, LogicalOrExpr target_94, VariableAccess target_3) {
		target_3.getTarget()=vfrag_3158
		and target_3.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_92.getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getLocation())
		and target_3.getLocation().isBefore(target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_4(Variable vfrag_3158, RelationalOperation target_92, LogicalOrExpr target_94, Literal target_4) {
		target_4.getValue()="0"
		and not target_4.getValue()="2"
		and target_4.getParent().(ArrayExpr).getParent().(NEExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_92.getLesserOperand().(VariableAccess).getLocation().isBefore(target_4.getParent().(ArrayExpr).getParent().(NEExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_4.getParent().(ArrayExpr).getParent().(NEExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
}

*/
predicate func_5(Variable vattr_3159, LogicalOrExpr target_94, VariableAccess target_5) {
		target_5.getTarget()=vattr_3159
		and target_5.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_6(Variable vfrag_3158, LogicalOrExpr target_94, VariableAccess target_6) {
		target_6.getTarget()=vfrag_3158
		and target_6.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getLocation())
}

/*predicate func_7(Variable vfrag_3158, LogicalOrExpr target_94, VariableAccess target_7) {
		target_7.getTarget()=vfrag_3158
		and target_7.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getLocation())
}

*/
/*predicate func_8(Variable vfrag_3158, LogicalOrExpr target_94, Literal target_8) {
		target_8.getValue()="2"
		and not target_8.getValue()="1"
		and target_8.getParent().(ArrayExpr).getParent().(NEExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getParent().(ArrayExpr).getParent().(NEExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

*/
predicate func_9(Variable vfrag_3158, LogicalOrExpr target_94, VariableAccess target_9) {
		target_9.getTarget()=vfrag_3158
		and target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getLocation())
}

predicate func_10(Variable vfrag_3158, ExprStmt target_95, VariableAccess target_10) {
		target_10.getTarget()=vfrag_3158
		and target_10.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_10.getLocation().isBefore(target_95.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

/*predicate func_11(Variable vfrag_3158, Variable vend_3158, LogicalOrExpr target_94, VariableAccess target_11) {
		target_11.getTarget()=vend_3158
		and target_11.getParent().(AssignExpr).getLValue() = target_11
		and target_11.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vfrag_3158
		and target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getParent().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

*/
/*predicate func_12(Variable vfrag_3158, Variable vend_3158, LogicalOrExpr target_94, VariableAccess target_12) {
		target_12.getTarget()=vfrag_3158
		and target_12.getParent().(AssignExpr).getRValue() = target_12
		and target_12.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_3158
		and target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_12.getLocation())
}

*/
/*predicate func_13(Variable vfrag_3158, ExprStmt target_95, ExprStmt target_98, VariableAccess target_13) {
		target_13.getTarget()=vfrag_3158
		and target_13.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_95.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_13.getLocation())
		and target_13.getLocation().isBefore(target_98.getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

*/
/*predicate func_14(Variable vfrag_3158, ExprStmt target_95, ExprStmt target_98, Literal target_14) {
		target_14.getValue()="3"
		and not target_14.getValue()="1"
		and target_14.getParent().(ArrayExpr).getParent().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_95.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_14.getParent().(ArrayExpr).getParent().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_14.getParent().(ArrayExpr).getParent().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_98.getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

*/
predicate func_15(Variable vfraglen_3156, Variable vfrag_3158, VariableAccess target_15) {
		target_15.getTarget()=vfraglen_3156
		and target_15.getParent().(AssignAddExpr).getLValue() = target_15
		and target_15.getParent().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_15.getParent().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_15.getParent().(AssignAddExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="4"
}

/*predicate func_16(Variable vfrag_3158, ExprStmt target_100, VariableAccess target_16) {
		target_16.getTarget()=vfrag_3158
		and target_16.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_16.getLocation().isBefore(target_100.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
}

*/
predicate func_17(Variable vfrag_3158, ExprStmt target_98, VariableAccess target_17) {
		target_17.getTarget()=vfrag_3158
		and target_98.getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_17.getLocation())
}

predicate func_18(Variable vfrag_3158, VariableAccess target_18) {
		target_18.getTarget()=vfrag_3158
		and target_18.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_19(Variable vfraglen_3156, VariableAccess target_19) {
		target_19.getTarget()=vfraglen_3156
		and target_19.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("malloc")
}

predicate func_20(Variable vfrag_3158, VariableAccess target_20) {
		target_20.getTarget()=vfrag_3158
}

predicate func_21(Variable vfrag_3158, ExprStmt target_102, VariableAccess target_21) {
		target_21.getTarget()=vfrag_3158
		and target_21.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_21.getLocation().isBefore(target_102.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

predicate func_22(Variable vfrag_3158, SubExpr target_103, ExprStmt target_104, VariableAccess target_22) {
		target_22.getTarget()=vfrag_3158
		and target_22.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_103.getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_22.getLocation())
		and target_22.getLocation().isBefore(target_104.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_23(Variable vfrag_3158, ExprStmt target_102, VariableAccess target_23) {
		target_23.getTarget()=vfrag_3158
		and target_102.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_23.getLocation())
}

predicate func_24(Variable vfrag_3158, VariableAccess target_24) {
		target_24.getTarget()=vfrag_3158
		and target_24.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

/*predicate func_25(Parameter vctx_3148, Parameter vpacket_3148, Parameter voriginal_3149, Parameter vsecret_3150, Parameter vda_3150, Parameter vpvp_3153, Variable vfraglen_3156, Variable vhead_3157, VariableAccess target_25) {
		target_25.getTarget()=vfraglen_3156
		and target_25.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("data2vp")
		and target_25.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_3148
		and target_25.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpacket_3148
		and target_25.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voriginal_3149
		and target_25.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vsecret_3150
		and target_25.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vda_3150
		and target_25.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vhead_3157
		and target_25.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vfraglen_3156
		and target_25.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vpvp_3153
}

*/
/*predicate func_26(Parameter vctx_3148, Parameter vpacket_3148, Parameter voriginal_3149, Parameter vsecret_3150, Parameter vda_3150, Parameter vpvp_3153, Variable vfraglen_3156, Variable vhead_3157, VariableAccess target_26) {
		target_26.getTarget()=vfraglen_3156
		and target_26.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("data2vp")
		and target_26.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_3148
		and target_26.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpacket_3148
		and target_26.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voriginal_3149
		and target_26.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vsecret_3150
		and target_26.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vda_3150
		and target_26.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vhead_3157
		and target_26.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vfraglen_3156
		and target_26.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vpvp_3153
}

*/
predicate func_27(Variable vlast_frag_3161, VariableAccess target_27) {
		target_27.getTarget()=vlast_frag_3161
		and target_27.getParent().(AssignExpr).getLValue() = target_27
		and target_27.getParent().(AssignExpr).getRValue() instanceof Literal
}

predicate func_28(Variable vlast_frag_3161, VariableAccess target_28) {
		target_28.getTarget()=vlast_frag_3161
}

predicate func_29(Variable vfrag_3158, Variable vattr_3159, ExprStmt target_100, PointerArithmeticOperation target_105, LogicalOrExpr target_94, VariableAccess target_29) {
		target_29.getTarget()=vfrag_3158
		and target_29.getParent().(AssignExpr).getLValue() = target_29
		and target_29.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vattr_3159
		and target_100.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_29.getLocation())
		and target_29.getLocation().isBefore(target_105.getAnOperand().(VariableAccess).getLocation())
}

predicate func_31(Parameter vctx_3148, Parameter vda_3150) {
	exists(AssignExpr target_31 |
		target_31.getLValue().(VariableAccess).getType().hasName("const DICT_ATTR *")
		and target_31.getRValue().(FunctionCall).getTarget().hasName("dict_unknown_afrom_fields")
		and target_31.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_3148
		and target_31.getRValue().(FunctionCall).getArgument(1).(BitwiseAndExpr).getLeftOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vendor"
		and target_31.getRValue().(FunctionCall).getArgument(1).(BitwiseAndExpr).getLeftOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vda_3150
		and target_31.getRValue().(FunctionCall).getArgument(1).(BitwiseAndExpr).getLeftOperand().(DivExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="16777216"
		and target_31.getRValue().(FunctionCall).getArgument(1).(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="255"
		and target_31.getRValue().(FunctionCall).getArgument(2) instanceof Literal)
}

predicate func_32(BlockStmt target_106, Function func) {
	exists(NotExpr target_32 |
		target_32.getOperand().(VariableAccess).getType().hasName("const DICT_ATTR *")
		and target_32.getParent().(IfStmt).getThen()=target_106
		and target_32.getEnclosingFunction() = func)
}

predicate func_33(Function func) {
	exists(FunctionCall target_33 |
		target_33.getTarget().hasName("fr_strerror_printf")
		and target_33.getArgument(0).(StringLiteral).getValue()="Internal sanity check %d"
		and target_33.getArgument(1).(Literal).getValue()="3177"
		and target_33.getEnclosingFunction() = func)
}

predicate func_34(Parameter vctx_3148, Parameter vpacket_3148, Parameter voriginal_3149, Parameter vsecret_3150, Parameter vdata_3151, Parameter vattrlen_3152, Parameter vpvp_3153, Variable vrcode_3155, ExprStmt target_91) {
	exists(AssignExpr target_34 |
		target_34.getLValue().(VariableAccess).getTarget()=vrcode_3155
		and target_34.getRValue().(FunctionCall).getTarget().hasName("data2vp")
		and target_34.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_3148
		and target_34.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpacket_3148
		and target_34.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voriginal_3149
		and target_34.getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vsecret_3150
		and target_34.getRValue().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("const DICT_ATTR *")
		and target_34.getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vdata_3151
		and target_34.getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vattrlen_3152
		and target_34.getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vattrlen_3152
		and target_34.getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vpvp_3153
		and target_34.getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_91.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_36(Parameter vctx_3148, Parameter vpacket_3148, Parameter voriginal_3149, Parameter vsecret_3150, Parameter vda_3150, Parameter vdata_3151, Parameter vattrlen_3152, Parameter vpvp_3153, Variable vrcode_3155, NotExpr target_62, ExprStmt target_108, ExprStmt target_93) {
	exists(ExprStmt target_36 |
		target_36.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrcode_3155
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("data2vp")
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_3148
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpacket_3148
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voriginal_3149
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vsecret_3150
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vda_3150
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_3151
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrlen_3152
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrlen_3152
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vpvp_3153
		and target_36.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_36
		and target_36.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_62
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_108.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_93.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_37(Parameter vattrlen_3152, Variable vrcode_3155, NotExpr target_62) {
	exists(IfStmt target_37 |
		target_37.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrcode_3155
		and target_37.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_37.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrcode_3155
		and target_37.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_37.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vattrlen_3152
		and target_37.getThen().(GotoStmt).toString() = "goto ..."
		and target_37.getThen().(GotoStmt).getName() ="raw"
		and target_37.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_37
		and target_37.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_62)
}

/*predicate func_38(Variable vrcode_3155, Variable vfrag_3158, Variable vend_3158, BlockStmt target_106) {
	exists(RelationalOperation target_38 |
		 (target_38 instanceof GTExpr or target_38 instanceof LTExpr)
		and target_38.getLesserOperand().(VariableAccess).getTarget()=vrcode_3155
		and target_38.getGreaterOperand() instanceof Literal
		and target_38.getParent().(LogicalOrExpr).getAnOperand() instanceof LogicalOrExpr
		and target_38.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vfrag_3158
		and target_38.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_38.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_38.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vend_3158
		and target_38.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_106)
}

*/
/*predicate func_39(Variable vrcode_3155) {
	exists(AddExpr target_39 |
		target_39.getAnOperand().(VariableAccess).getTarget()=vrcode_3155
		and target_39.getAnOperand().(Literal).getValue()="2")
}

*/
predicate func_41(Parameter vattrlen_3152, NotExpr target_62) {
	exists(ReturnStmt target_41 |
		target_41.getExpr().(VariableAccess).getTarget()=vattrlen_3152
		and target_41.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_41
		and target_41.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_62)
}

predicate func_42(Parameter vattrlen_3152, Parameter vpacketlen_3152, RelationalOperation target_109, ExprStmt target_90, Function func) {
	exists(IfStmt target_42 |
		target_42.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vattrlen_3152
		and target_42.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vpacketlen_3152
		and target_42.getThen().(GotoStmt).toString() = "goto ..."
		and target_42.getThen().(GotoStmt).getName() ="raw"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_42 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_42)
		and target_109.getLesserOperand().(VariableAccess).getLocation().isBefore(target_42.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_42.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_90.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_43(Variable vend_3158, Variable vattr_3159, LogicalOrExpr target_94) {
	exists(IfStmt target_43 |
		target_43.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_3158
		and target_43.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vattr_3159
		and target_43.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_43.getThen().(GotoStmt).toString() = "goto ..."
		and target_43.getThen().(GotoStmt).getName() ="raw")
}

predicate func_44(Function func) {
	exists(IfStmt target_44 |
		target_44.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("const uint8_t *")
		and target_44.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_44.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_44.getThen().(GotoStmt).toString() = "goto ..."
		and target_44.getThen().(GotoStmt).getName() ="raw"
		and target_44.getEnclosingFunction() = func)
}

predicate func_45(Variable vend_3158, RelationalOperation target_92) {
	exists(IfStmt target_45 |
		target_45.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("const uint8_t *")
		and target_45.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("const uint8_t *")
		and target_45.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_45.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vend_3158
		and target_45.getThen().(GotoStmt).toString() = "goto ..."
		and target_45.getThen().(GotoStmt).getName() ="raw"
		and target_92.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_45.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_46(Parameter vda_3150, ExprStmt target_108) {
	exists(IfStmt target_46 |
		target_46.getCondition().(EqualityOperation).getAnOperand() instanceof ArrayExpr
		and target_46.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vendor"
		and target_46.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vda_3150
		and target_46.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(DivExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="16777216"
		and target_46.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="255"
		and target_46.getThen().(GotoStmt).toString() = "goto ..."
		and target_46.getThen().(GotoStmt).getName() ="raw"
		and target_46.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_108.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation()))
}

predicate func_47(Function func) {
	exists(IfStmt target_47 |
		target_47.getCondition().(EqualityOperation).getAnOperand() instanceof ArrayExpr
		and target_47.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("const uint8_t *")
		and target_47.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_47.getThen().(GotoStmt).toString() = "goto ..."
		and target_47.getThen().(GotoStmt).getName() ="raw"
		and target_47.getEnclosingFunction() = func)
}

/*predicate func_48(Function func) {
	exists(ArrayExpr target_48 |
		target_48.getArrayBase().(VariableAccess).getType().hasName("const uint8_t *")
		and target_48.getArrayOffset().(Literal).getValue()="0"
		and target_48.getEnclosingFunction() = func)
}

*/
predicate func_49(Variable vattr_3159, Variable vlast_frag_3161, LogicalOrExpr target_94) {
	exists(EqualityOperation target_49 |
		target_49.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vattr_3159
		and target_49.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_49.getAnOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="128"
		and target_49.getAnOperand().(Literal).getValue()="0"
		and target_49.getParent().(AssignExpr).getRValue() = target_49
		and target_49.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlast_frag_3161)
}

predicate func_50(Variable vattr_3159, ExprStmt target_110) {
	exists(IfStmt target_50 |
		target_50.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_50.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("const uint8_t *")
		and target_50.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vattr_3159
		and target_50.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vattr_3159
		and target_50.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_110.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_50.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_51(Variable vattr_3159, ExprStmt target_110) {
	exists(PointerArithmeticOperation target_51 |
		target_51.getAnOperand().(VariableAccess).getTarget()=vattr_3159
		and target_51.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vattr_3159
		and target_51.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_51.getParent().(AssignExpr).getRValue() = target_51
		and target_51.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattr_3159
		and target_110.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_51.getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_52(Variable vend_3158, Variable vattr_3159, PointerArithmeticOperation target_111) {
	exists(IfStmt target_52 |
		target_52.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getType().hasName("bool")
		and target_52.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vattr_3159
		and target_52.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vattr_3159
		and target_52.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_52.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vend_3158
		and target_52.getThen().(GotoStmt).toString() = "goto ..."
		and target_52.getThen().(GotoStmt).getName() ="raw"
		and target_52.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_111.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_53(Function func) {
	exists(IfStmt target_53 |
		target_53.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_53.getThen() instanceof BreakStmt
		and target_53.getEnclosingFunction() = func)
}

predicate func_55(Function func) {
	exists(IfStmt target_55 |
		target_55.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("size_t")
		and target_55.getThen().(GotoStmt).toString() = "goto ..."
		and target_55.getThen().(GotoStmt).getName() ="raw"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_55 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_55))
}

predicate func_56(Function func) {
	exists(IfStmt target_56 |
		target_56.getCondition() instanceof NotExpr
		and target_56.getThen().(GotoStmt).toString() = "goto ..."
		and target_56.getThen().(GotoStmt).getName() ="raw"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_56 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_56))
}

predicate func_57(Parameter vattrlen_3152, Variable vtail_3157, Variable vattr_3159, ExprStmt target_93) {
	exists(FunctionCall target_57 |
		target_57.getTarget().hasName("memcpy")
		and target_57.getArgument(0).(VariableAccess).getTarget()=vtail_3157
		and target_57.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vattr_3159
		and target_57.getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_57.getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrlen_3152
		and target_57.getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_93.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_57.getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_58(Parameter vattrlen_3152, Variable vtail_3157) {
	exists(AssignPointerAddExpr target_58 |
		target_58.getLValue().(VariableAccess).getTarget()=vtail_3157
		and target_58.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrlen_3152
		and target_58.getRValue().(SubExpr).getRightOperand().(Literal).getValue()="2")
}

predicate func_59(Parameter vattrlen_3152, Variable vattr_3159) {
	exists(AssignPointerAddExpr target_59 |
		target_59.getLValue().(VariableAccess).getTarget()=vattr_3159
		and target_59.getRValue().(VariableAccess).getTarget()=vattrlen_3152)
}

predicate func_60(Variable vend_3158, Variable vattr_3159, ExprStmt target_95) {
	exists(RelationalOperation target_60 |
		 (target_60 instanceof GTExpr or target_60 instanceof LTExpr)
		and target_60.getLesserOperand().(VariableAccess).getTarget()=vattr_3159
		and target_60.getGreaterOperand().(VariableAccess).getTarget()=vend_3158
		and target_95.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_60.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_61(Variable vrcode_3155, Function func) {
	exists(IfStmt target_61 |
		target_61.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrcode_3155
		and target_61.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_61.getThen().(GotoStmt).toString() = "goto ..."
		and target_61.getThen().(GotoStmt).getName() ="raw"
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_61 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_61))
}

predicate func_62(Variable vhead_3157, ReturnStmt target_113, NotExpr target_62) {
		target_62.getOperand().(VariableAccess).getTarget()=vhead_3157
		and target_62.getParent().(IfStmt).getThen()=target_113
}

predicate func_63(Variable vrcode_3155, Function func, IfStmt target_63) {
		target_63.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrcode_3155
		and target_63.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_63.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vrcode_3155
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_63
}

predicate func_64(RelationalOperation target_109, Function func, ReturnStmt target_64) {
		target_64.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_64.getParent().(IfStmt).getCondition()=target_109
		and target_64.getEnclosingFunction() = func
}

predicate func_65(Variable vattr_3159, ArrayExpr target_65) {
		target_65.getArrayBase().(VariableAccess).getTarget()=vattr_3159
		and target_65.getArrayOffset().(Literal).getValue()="0"
}

predicate func_66(Variable vattr_3159, ArrayExpr target_66) {
		target_66.getArrayBase().(VariableAccess).getTarget()=vattr_3159
		and target_66.getArrayOffset().(Literal).getValue()="2"
}

predicate func_67(Variable vattr_3159, VariableAccess target_67) {
		target_67.getTarget()=vattr_3159
		and target_67.getParent().(AssignExpr).getLValue() = target_67
		and target_67.getParent().(AssignExpr).getRValue() instanceof PointerArithmeticOperation
}

predicate func_68(Parameter vdata_3151, VariableAccess target_68) {
		target_68.getTarget()=vdata_3151
}

predicate func_72(LogicalOrExpr target_94, Function func, BreakStmt target_72) {
		target_72.toString() = "break;"
		and target_72.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_94
		and target_72.getEnclosingFunction() = func
}

predicate func_74(Variable vfrag_3158, Variable vattr_3159, VariableAccess target_74) {
		target_74.getTarget()=vattr_3159
		and target_74.getParent().(AssignExpr).getRValue() = target_74
		and target_74.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag_3158
}

predicate func_76(Function func, LabelStmt target_76) {
		target_76.toString() = "label ...:"
		and target_76.getEnclosingFunction() = func
}

predicate func_78(Function func, DeclStmt target_78) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_78
}

predicate func_79(Parameter vdata_3151, Variable vattr_3159, PointerArithmeticOperation target_79) {
		target_79.getLeftOperand().(VariableAccess).getTarget()=vdata_3151
		and target_79.getRightOperand() instanceof Literal
		and target_79.getParent().(AssignExpr).getRValue() = target_79
		and target_79.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattr_3159
}

predicate func_80(Variable vfragments_3160, AssignExpr target_80) {
		target_80.getLValue().(VariableAccess).getTarget()=vfragments_3160
		and target_80.getRValue() instanceof Literal
}

predicate func_81(Variable vfrag_3158, Variable vend_3158, Variable vlast_frag_3161, BlockStmt target_106, LogicalOrExpr target_81) {
		target_81.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=vlast_frag_3161
		and target_81.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_81.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_81.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof ArrayExpr
		and target_81.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_81.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_81.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_81.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_81.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_81.getAnOperand().(EqualityOperation).getAnOperand() instanceof ArrayExpr
		and target_81.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vfrag_3158
		and target_81.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_81.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_81.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vend_3158
		and target_81.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_106
}

predicate func_82(Variable vfrag_3158, Variable vlast_frag_3161, AssignExpr target_82) {
		target_82.getLValue().(VariableAccess).getTarget()=vlast_frag_3161
		and target_82.getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_82.getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_82.getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="128"
		and target_82.getRValue().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_83(Variable vfragments_3160, PostfixIncrExpr target_83) {
		target_83.getOperand().(VariableAccess).getTarget()=vfragments_3160
}

predicate func_84(Function func, UnaryMinusExpr target_84) {
		target_84.getValue()="-1"
		and target_84.getEnclosingFunction() = func
}

predicate func_85(Variable vfrag_3158, Variable vattr_3159, AssignExpr target_85) {
		target_85.getLValue().(VariableAccess).getTarget()=vfrag_3158
		and target_85.getRValue().(VariableAccess).getTarget()=vattr_3159
}

predicate func_86(Variable vfragments_3160, RelationalOperation target_86) {
		 (target_86 instanceof GTExpr or target_86 instanceof LTExpr)
		and target_86.getGreaterOperand().(VariableAccess).getTarget()=vfragments_3160
		and target_86.getLesserOperand() instanceof Literal
}

predicate func_87(Variable vfragments_3160, PostfixDecrExpr target_87) {
		target_87.getOperand().(VariableAccess).getTarget()=vfragments_3160
}

predicate func_88(Function func, EmptyStmt target_88) {
		target_88.toString() = ";"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_88
}

predicate func_90(Parameter vdata_3151, Parameter vpacketlen_3152, Variable vend_3158, ExprStmt target_90) {
		target_90.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_3158
		and target_90.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_3151
		and target_90.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vpacketlen_3152
}

predicate func_91(Parameter vattrlen_3152, Variable vfraglen_3156, ExprStmt target_91) {
		target_91.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfraglen_3156
		and target_91.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrlen_3152
		and target_91.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_92(Variable vfrag_3158, Variable vend_3158, RelationalOperation target_92) {
		 (target_92 instanceof GTExpr or target_92 instanceof LTExpr)
		and target_92.getLesserOperand().(VariableAccess).getTarget()=vfrag_3158
		and target_92.getGreaterOperand().(VariableAccess).getTarget()=vend_3158
}

predicate func_93(Parameter vdata_3151, Parameter vattrlen_3152, Variable vfrag_3158, ExprStmt target_93) {
		target_93.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag_3158
		and target_93.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_3151
		and target_93.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vattrlen_3152
}

predicate func_94(Variable vfrag_3158, Variable vend_3158, LogicalOrExpr target_94) {
		target_94.getAnOperand() instanceof LogicalOrExpr
		and target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vfrag_3158
		and target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_94.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vend_3158
}

predicate func_95(Variable vfrag_3158, Variable vend_3158, ExprStmt target_95) {
		target_95.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_3158
		and target_95.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vfrag_3158
}

predicate func_98(Variable vfraglen_3156, Variable vfrag_3158, ExprStmt target_98) {
		target_98.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vfraglen_3156
		and target_98.getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_98.getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_98.getExpr().(AssignAddExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="4"
}

predicate func_100(Variable vfrag_3158, ExprStmt target_100) {
		target_100.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vfrag_3158
		and target_100.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_100.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_102(Variable vtail_3157, Variable vfrag_3158, ExprStmt target_102) {
		target_102.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vtail_3157
		and target_102.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_102.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_102.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="4"
}

predicate func_103(Variable vfrag_3158, SubExpr target_103) {
		target_103.getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_103.getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_103.getRightOperand().(Literal).getValue()="4"
}

predicate func_104(Variable vfrag_3158, ExprStmt target_104) {
		target_104.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vfrag_3158
		and target_104.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfrag_3158
		and target_104.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_105(Variable vfrag_3158, PointerArithmeticOperation target_105) {
		target_105.getAnOperand().(VariableAccess).getTarget()=vfrag_3158
		and target_105.getAnOperand().(Literal).getValue()="4"
}

predicate func_106(Variable vfrag_3158, Variable vend_3158, BlockStmt target_106) {
		target_106.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_3158
		and target_106.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vfrag_3158
		and target_106.getStmt(1) instanceof BreakStmt
}

predicate func_108(Parameter vctx_3148, Parameter vpacket_3148, Parameter voriginal_3149, Parameter vsecret_3150, Parameter vda_3150, Parameter vpvp_3153, Variable vrcode_3155, Variable vfraglen_3156, Variable vhead_3157, ExprStmt target_108) {
		target_108.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrcode_3155
		and target_108.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("data2vp")
		and target_108.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_3148
		and target_108.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpacket_3148
		and target_108.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voriginal_3149
		and target_108.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vsecret_3150
		and target_108.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vda_3150
		and target_108.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vhead_3157
		and target_108.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vfraglen_3156
		and target_108.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vfraglen_3156
		and target_108.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vpvp_3153
}

predicate func_109(Parameter vattrlen_3152, RelationalOperation target_109) {
		 (target_109 instanceof GTExpr or target_109 instanceof LTExpr)
		and target_109.getLesserOperand().(VariableAccess).getTarget()=vattrlen_3152
		and target_109.getGreaterOperand().(Literal).getValue()="3"
}

predicate func_110(Variable vattr_3159, ExprStmt target_110) {
		target_110.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattr_3159
		and target_110.getExpr().(AssignExpr).getRValue() instanceof PointerArithmeticOperation
}

predicate func_111(Parameter vdata_3151, Variable vend_3158, PointerArithmeticOperation target_111) {
		target_111.getLeftOperand().(VariableAccess).getTarget()=vend_3158
		and target_111.getRightOperand().(VariableAccess).getTarget()=vdata_3151
}

predicate func_113(ReturnStmt target_113) {
		target_113.getExpr() instanceof UnaryMinusExpr
}

from Function func, Parameter vctx_3148, Parameter vpacket_3148, Parameter voriginal_3149, Parameter vsecret_3150, Parameter vda_3150, Parameter vdata_3151, Parameter vattrlen_3152, Parameter vpacketlen_3152, Parameter vpvp_3153, Variable vrcode_3155, Variable vfraglen_3156, Variable vhead_3157, Variable vtail_3157, Variable vfrag_3158, Variable vend_3158, Variable vattr_3159, Variable vfragments_3160, Variable vlast_frag_3161, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_5, VariableAccess target_6, VariableAccess target_9, VariableAccess target_10, VariableAccess target_15, VariableAccess target_17, VariableAccess target_18, VariableAccess target_19, VariableAccess target_20, VariableAccess target_21, VariableAccess target_22, VariableAccess target_23, VariableAccess target_24, VariableAccess target_27, VariableAccess target_28, VariableAccess target_29, NotExpr target_62, IfStmt target_63, ReturnStmt target_64, ArrayExpr target_65, ArrayExpr target_66, VariableAccess target_67, VariableAccess target_68, BreakStmt target_72, VariableAccess target_74, LabelStmt target_76, DeclStmt target_78, PointerArithmeticOperation target_79, AssignExpr target_80, LogicalOrExpr target_81, AssignExpr target_82, PostfixIncrExpr target_83, UnaryMinusExpr target_84, AssignExpr target_85, RelationalOperation target_86, PostfixDecrExpr target_87, EmptyStmt target_88, ExprStmt target_90, ExprStmt target_91, RelationalOperation target_92, ExprStmt target_93, LogicalOrExpr target_94, ExprStmt target_95, ExprStmt target_98, ExprStmt target_100, ExprStmt target_102, SubExpr target_103, ExprStmt target_104, PointerArithmeticOperation target_105, BlockStmt target_106, ExprStmt target_108, RelationalOperation target_109, ExprStmt target_110, PointerArithmeticOperation target_111, ReturnStmt target_113
where
func_0(vattrlen_3152, vfraglen_3156, target_0)
and func_1(vdata_3151, vattrlen_3152, vfrag_3158, target_90, target_91, target_92, target_1)
and func_2(vfrag_3158, vend_3158, target_93, target_94, target_90, target_2)
and func_5(vattr_3159, target_94, target_5)
and func_6(vfrag_3158, target_94, target_6)
and func_9(vfrag_3158, target_94, target_9)
and func_10(vfrag_3158, target_95, target_10)
and func_15(vfraglen_3156, vfrag_3158, target_15)
and func_17(vfrag_3158, target_98, target_17)
and func_18(vfrag_3158, target_18)
and func_19(vfraglen_3156, target_19)
and func_20(vfrag_3158, target_20)
and func_21(vfrag_3158, target_102, target_21)
and func_22(vfrag_3158, target_103, target_104, target_22)
and func_23(vfrag_3158, target_102, target_23)
and func_24(vfrag_3158, target_24)
and func_27(vlast_frag_3161, target_27)
and func_28(vlast_frag_3161, target_28)
and func_29(vfrag_3158, vattr_3159, target_100, target_105, target_94, target_29)
and not func_31(vctx_3148, vda_3150)
and not func_32(target_106, func)
and not func_33(func)
and not func_34(vctx_3148, vpacket_3148, voriginal_3149, vsecret_3150, vdata_3151, vattrlen_3152, vpvp_3153, vrcode_3155, target_91)
and not func_36(vctx_3148, vpacket_3148, voriginal_3149, vsecret_3150, vda_3150, vdata_3151, vattrlen_3152, vpvp_3153, vrcode_3155, target_62, target_108, target_93)
and not func_37(vattrlen_3152, vrcode_3155, target_62)
and not func_41(vattrlen_3152, target_62)
and not func_42(vattrlen_3152, vpacketlen_3152, target_109, target_90, func)
and not func_43(vend_3158, vattr_3159, target_94)
and not func_44(func)
and not func_45(vend_3158, target_92)
and not func_46(vda_3150, target_108)
and not func_47(func)
and not func_49(vattr_3159, vlast_frag_3161, target_94)
and not func_50(vattr_3159, target_110)
and not func_52(vend_3158, vattr_3159, target_111)
and not func_53(func)
and not func_55(func)
and not func_56(func)
and not func_57(vattrlen_3152, vtail_3157, vattr_3159, target_93)
and not func_58(vattrlen_3152, vtail_3157)
and not func_59(vattrlen_3152, vattr_3159)
and not func_60(vend_3158, vattr_3159, target_95)
and not func_61(vrcode_3155, func)
and func_62(vhead_3157, target_113, target_62)
and func_63(vrcode_3155, func, target_63)
and func_64(target_109, func, target_64)
and func_65(vattr_3159, target_65)
and func_66(vattr_3159, target_66)
and func_67(vattr_3159, target_67)
and func_68(vdata_3151, target_68)
and func_72(target_94, func, target_72)
and func_74(vfrag_3158, vattr_3159, target_74)
and func_76(func, target_76)
and func_78(func, target_78)
and func_79(vdata_3151, vattr_3159, target_79)
and func_80(vfragments_3160, target_80)
and func_81(vfrag_3158, vend_3158, vlast_frag_3161, target_106, target_81)
and func_82(vfrag_3158, vlast_frag_3161, target_82)
and func_83(vfragments_3160, target_83)
and func_84(func, target_84)
and func_85(vfrag_3158, vattr_3159, target_85)
and func_86(vfragments_3160, target_86)
and func_87(vfragments_3160, target_87)
and func_88(func, target_88)
and func_90(vdata_3151, vpacketlen_3152, vend_3158, target_90)
and func_91(vattrlen_3152, vfraglen_3156, target_91)
and func_92(vfrag_3158, vend_3158, target_92)
and func_93(vdata_3151, vattrlen_3152, vfrag_3158, target_93)
and func_94(vfrag_3158, vend_3158, target_94)
and func_95(vfrag_3158, vend_3158, target_95)
and func_98(vfraglen_3156, vfrag_3158, target_98)
and func_100(vfrag_3158, target_100)
and func_102(vtail_3157, vfrag_3158, target_102)
and func_103(vfrag_3158, target_103)
and func_104(vfrag_3158, target_104)
and func_105(vfrag_3158, target_105)
and func_106(vfrag_3158, vend_3158, target_106)
and func_108(vctx_3148, vpacket_3148, voriginal_3149, vsecret_3150, vda_3150, vpvp_3153, vrcode_3155, vfraglen_3156, vhead_3157, target_108)
and func_109(vattrlen_3152, target_109)
and func_110(vattr_3159, target_110)
and func_111(vdata_3151, vend_3158, target_111)
and func_113(target_113)
and vctx_3148.getType().hasName("TALLOC_CTX *")
and vpacket_3148.getType().hasName("RADIUS_PACKET *")
and voriginal_3149.getType().hasName("const RADIUS_PACKET *")
and vsecret_3150.getType().hasName("const char *")
and vda_3150.getType().hasName("const DICT_ATTR *")
and vdata_3151.getType().hasName("const uint8_t *")
and vattrlen_3152.getType().hasName("size_t")
and vpacketlen_3152.getType().hasName("size_t")
and vpvp_3153.getType().hasName("VALUE_PAIR **")
and vrcode_3155.getType().hasName("ssize_t")
and vfraglen_3156.getType().hasName("size_t")
and vhead_3157.getType().hasName("uint8_t *")
and vtail_3157.getType().hasName("uint8_t *")
and vfrag_3158.getType().hasName("const uint8_t *")
and vend_3158.getType().hasName("const uint8_t *")
and vattr_3159.getType().hasName("const uint8_t *")
and vfragments_3160.getType().hasName("int")
and vlast_frag_3161.getType().hasName("bool")
and vctx_3148.getParentScope+() = func
and vpacket_3148.getParentScope+() = func
and voriginal_3149.getParentScope+() = func
and vsecret_3150.getParentScope+() = func
and vda_3150.getParentScope+() = func
and vdata_3151.getParentScope+() = func
and vattrlen_3152.getParentScope+() = func
and vpacketlen_3152.getParentScope+() = func
and vpvp_3153.getParentScope+() = func
and vrcode_3155.getParentScope+() = func
and vfraglen_3156.getParentScope+() = func
and vhead_3157.getParentScope+() = func
and vtail_3157.getParentScope+() = func
and vfrag_3158.getParentScope+() = func
and vend_3158.getParentScope+() = func
and vattr_3159.getParentScope+() = func
and vfragments_3160.getParentScope+() = func
and vlast_frag_3161.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
