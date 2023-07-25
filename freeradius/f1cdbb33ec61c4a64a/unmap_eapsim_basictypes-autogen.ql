/**
 * @name freeradius-f1cdbb33ec61c4a64a-unmap_eapsim_basictypes
 * @id cpp/freeradius/f1cdbb33ec61c4a64a/unmap-eapsim-basictypes
 * @description freeradius-f1cdbb33ec61c4a64a-src/modules/rlm_eap/libeap/eapsimlib.c-unmap_eapsim_basictypes CVE-2022-41860
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="EAP-Sim attribute %d (no.%d) has length too small"
		and not target_0.getValue()="EAP-Sim attribute %d (no.%d) has no data"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="254"
		and not target_1.getValue()="1"
		and target_1.getParent().(GTExpr).getParent().(IfStmt).getCondition() instanceof RelationalOperation
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="254"
		and not target_2.getValue()="127"
		and target_2.getParent().(AssignExpr).getParent().(ExprStmt).getExpr() instanceof AssignExpr
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Parameter vattr_285, BlockStmt target_17, ExprStmt target_18, AddressOfExpr target_19) {
	exists(NotExpr target_3 |
		target_3.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vattr_285
		and target_3.getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_3.getParent().(IfStmt).getThen()=target_17
		and target_18.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_3.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_3.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_19.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_4(Variable vnewvp_287, BlockStmt target_20, ExprStmt target_21) {
	exists(NotExpr target_4 |
		target_4.getOperand().(VariableAccess).getTarget()=vnewvp_287
		and target_4.getParent().(IfStmt).getThen()=target_20
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable veapsim_attribute_288, RelationalOperation target_12, ExprStmt target_22, ExprStmt target_23) {
	exists(IfStmt target_5 |
		target_5.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=veapsim_attribute_288
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="127"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fr_strerror_printf")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="Unknown mandatory attribute %d, failing"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=veapsim_attribute_288
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr() instanceof Literal
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_22.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_5.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_23.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

/*predicate func_6(Variable veapsim_attribute_288, ExprStmt target_23) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("fr_strerror_printf")
		and target_6.getArgument(0).(StringLiteral).getValue()="Unknown mandatory attribute %d, failing"
		and target_6.getArgument(1).(VariableAccess).getTarget()=veapsim_attribute_288
		and target_6.getArgument(1).(VariableAccess).getLocation().isBefore(target_23.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

*/
predicate func_7(Variable vnewvp_287, ExprStmt target_9, ExprStmt target_10) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="length"
		and target_7.getQualifier().(VariableAccess).getTarget()=vnewvp_287
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getQualifier().(VariableAccess).getLocation())
		and target_7.getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_8(Variable vnewvp_287, Variable veapsim_len_289, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewvp_287
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=veapsim_len_289
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_9(Variable vp_315, Variable vnewvp_287, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="octets"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewvp_287
		and target_9.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_315
		and target_9.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_talloc_array")
		and target_9.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewvp_287
		and target_9.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="1"
		and target_9.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="length"
		and target_9.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewvp_287
		and target_9.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(StringLiteral).getValue()="uint8_t"
}

predicate func_10(Parameter vr_284, Variable vnewvp_287, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("fr_pair_add")
		and target_10.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="vps"
		and target_10.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_284
		and target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnewvp_287
}

predicate func_12(Variable veapsim_len_289, BlockStmt target_17, RelationalOperation target_12) {
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getGreaterOperand().(VariableAccess).getTarget()=veapsim_len_289
		and target_12.getLesserOperand() instanceof Literal
		and target_12.getParent().(IfStmt).getThen()=target_17
}

predicate func_13(Variable veapsim_len_289, AssignExpr target_13) {
		target_13.getLValue().(VariableAccess).getTarget()=veapsim_len_289
		and target_13.getRValue() instanceof Literal
}

predicate func_14(Variable veapsim_len_289, BlockStmt target_20, RelationalOperation target_14) {
		 (target_14 instanceof GTExpr or target_14 instanceof LTExpr)
		and target_14.getLesserOperand().(VariableAccess).getTarget()=veapsim_len_289
		and target_14.getGreaterOperand().(Literal).getValue()="2"
		and target_14.getParent().(IfStmt).getThen()=target_20
}

predicate func_15(Variable vp_315, Parameter vattr_285, Variable veapsim_len_289, ExprStmt target_9, ExprStmt target_24, ExprStmt target_8, SubExpr target_15) {
		target_15.getLeftOperand().(VariableAccess).getTarget()=veapsim_len_289
		and target_15.getRightOperand().(Literal).getValue()="2"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_315
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vattr_285
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_9.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_24.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_15.getLeftOperand().(VariableAccess).getLocation())
}

predicate func_16(Variable vnewvp_287, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewvp_287
		and target_16.getExpr().(AssignExpr).getRValue() instanceof Literal
}

predicate func_17(BlockStmt target_17) {
		target_17.getStmt(0).(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_18(Parameter vattr_285, Variable veapsim_len_289, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=veapsim_len_289
		and target_18.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vattr_285
		and target_18.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_18.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="4"
}

predicate func_19(Parameter vattr_285, AddressOfExpr target_19) {
		target_19.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vattr_285
		and target_19.getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
}

predicate func_20(Variable veapsim_attribute_288, BlockStmt target_20) {
		target_20.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fr_strerror_printf")
		and target_20.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_20.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=veapsim_attribute_288
		and target_20.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_21(Parameter vr_284, Variable vnewvp_287, ExprStmt target_21) {
		target_21.getExpr().(FunctionCall).getTarget().hasName("fr_pair_add")
		and target_21.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="vps"
		and target_21.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_284
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnewvp_287
}

predicate func_22(Variable veapsim_attribute_288, Variable veapsim_len_289, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("fr_strerror_printf")
		and target_22.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="EAP-Sim attribute %d (no.%d) has length longer than data (%d > %d)"
		and target_22.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=veapsim_attribute_288
		and target_22.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=veapsim_len_289
}

predicate func_23(Variable veapsim_attribute_288, ExprStmt target_23) {
		target_23.getExpr().(FunctionCall).getTarget().hasName("fr_strerror_printf")
		and target_23.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_23.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=veapsim_attribute_288
}

predicate func_24(Parameter vattr_285, Variable veapsim_len_289, ExprStmt target_24) {
		target_24.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vattr_285
		and target_24.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=veapsim_len_289
}

from Function func, Variable vp_315, Parameter vr_284, Parameter vattr_285, Variable vnewvp_287, Variable veapsim_attribute_288, Variable veapsim_len_289, StringLiteral target_0, Literal target_1, Literal target_2, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, RelationalOperation target_12, AssignExpr target_13, RelationalOperation target_14, SubExpr target_15, ExprStmt target_16, BlockStmt target_17, ExprStmt target_18, AddressOfExpr target_19, BlockStmt target_20, ExprStmt target_21, ExprStmt target_22, ExprStmt target_23, ExprStmt target_24
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and not func_3(vattr_285, target_17, target_18, target_19)
and not func_4(vnewvp_287, target_20, target_21)
and not func_5(veapsim_attribute_288, target_12, target_22, target_23)
and not func_7(vnewvp_287, target_9, target_10)
and func_8(vnewvp_287, veapsim_len_289, target_8)
and func_9(vp_315, vnewvp_287, target_9)
and func_10(vr_284, vnewvp_287, target_10)
and func_12(veapsim_len_289, target_17, target_12)
and func_13(veapsim_len_289, target_13)
and func_14(veapsim_len_289, target_20, target_14)
and func_15(vp_315, vattr_285, veapsim_len_289, target_9, target_24, target_8, target_15)
and func_16(vnewvp_287, target_16)
and func_17(target_17)
and func_18(vattr_285, veapsim_len_289, target_18)
and func_19(vattr_285, target_19)
and func_20(veapsim_attribute_288, target_20)
and func_21(vr_284, vnewvp_287, target_21)
and func_22(veapsim_attribute_288, veapsim_len_289, target_22)
and func_23(veapsim_attribute_288, target_23)
and func_24(vattr_285, veapsim_len_289, target_24)
and vp_315.getType().hasName("uint8_t *")
and vr_284.getType().hasName("RADIUS_PACKET *")
and vattr_285.getType().hasName("uint8_t *")
and vnewvp_287.getType().hasName("VALUE_PAIR *")
and veapsim_attribute_288.getType().hasName("int")
and veapsim_len_289.getType().hasName("unsigned int")
and vp_315.getParentScope+() = func
and vr_284.getParentScope+() = func
and vattr_285.getParentScope+() = func
and vnewvp_287.getParentScope+() = func
and veapsim_attribute_288.getParentScope+() = func
and veapsim_len_289.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
