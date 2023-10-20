/**
 * @name freeradius-19a18bf7c8af649c9e9742fb6a046f6aff639866-fr_dhcp_decode_suboption
 * @id cpp/freeradius/19a18bf7c8af649c9e9742fb6a046f6aff639866/fr-dhcp-decode-suboption
 * @description freeradius-19a18bf7c8af649c9e9742fb6a046f6aff639866-src/modules/proto_dhcp/dhcp.c-fr_dhcp_decode_suboption CVE-2017-10987
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_571, Parameter vlen_571, Variable vp_573, Variable vhead_574, ExprStmt target_2, ExprStmt target_3, RelationalOperation target_4, AddressOfExpr target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_573
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_571
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_571
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fr_pair_list_free")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vhead_574
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_4.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdata_571, Parameter vlen_571, Variable vp_573, Variable vhead_574, ExprStmt target_6, ExprStmt target_7, AddressOfExpr target_8) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_573
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_573
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_571
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_571
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fr_pair_list_free")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vhead_574
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_8.getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vdata_571, Variable vp_573, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_573
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdata_571
}

predicate func_3(Parameter vdata_571, Parameter vlen_571, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_571
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_571
}

predicate func_4(Variable vp_573, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vp_573
}

predicate func_5(Variable vhead_574, AddressOfExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vhead_574
}

predicate func_6(Parameter vdata_571, Parameter vlen_571, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("fr_pair_value_memcpy")
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_571
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_571
}

predicate func_7(Variable vp_573, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="attr"
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="da"
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="attr"
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="da"
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_573
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_573
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_8(Variable vhead_574, AddressOfExpr target_8) {
		target_8.getOperand().(VariableAccess).getTarget()=vhead_574
}

from Function func, Parameter vdata_571, Parameter vlen_571, Variable vp_573, Variable vhead_574, ExprStmt target_2, ExprStmt target_3, RelationalOperation target_4, AddressOfExpr target_5, ExprStmt target_6, ExprStmt target_7, AddressOfExpr target_8
where
not func_0(vdata_571, vlen_571, vp_573, vhead_574, target_2, target_3, target_4, target_5)
and not func_1(vdata_571, vlen_571, vp_573, vhead_574, target_6, target_7, target_8)
and func_2(vdata_571, vp_573, target_2)
and func_3(vdata_571, vlen_571, target_3)
and func_4(vp_573, target_4)
and func_5(vhead_574, target_5)
and func_6(vdata_571, vlen_571, target_6)
and func_7(vp_573, target_7)
and func_8(vhead_574, target_8)
and vdata_571.getType().hasName("const uint8_t *")
and vlen_571.getType().hasName("size_t")
and vp_573.getType().hasName("const uint8_t *")
and vhead_574.getType().hasName("VALUE_PAIR *")
and vdata_571.getParentScope+() = func
and vlen_571.getParentScope+() = func
and vp_573.getParentScope+() = func
and vhead_574.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
