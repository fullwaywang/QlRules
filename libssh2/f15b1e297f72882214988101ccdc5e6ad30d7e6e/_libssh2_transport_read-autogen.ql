/**
 * @name libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-_libssh2_transport_read
 * @id cpp/libssh2/f15b1e297f72882214988101ccdc5e6ad30d7e6e/-libssh2-transport-read
 * @description libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-src/transport.c-_libssh2_transport_read CVE-2019-3862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_276, RelationalOperation target_8, RelationalOperation target_9, ExprStmt target_10) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="padding_length"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="packet_length"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getElse().(IfStmt).getElse()=target_0
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_1(RelationalOperation target_11, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_1.getEnclosingFunction() = func)
}

*/
predicate func_2(Variable vp_276, Variable vblock_281, Variable vblocksize_282, Variable vtotal_num_284, RelationalOperation target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, ExprStmt target_17) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vblocksize_282
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="5"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtotal_num_284
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="wptr"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vblock_281
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="5"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vblocksize_282
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="5"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="wptr"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vblocksize_282
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="5"
		and target_2.getElse().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-41"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_15.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getLocation())
		and target_17.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vp_276, Variable vnumbytes_279, Variable vtotal_num_284, RelationalOperation target_11, ExprStmt target_18, ExprStmt target_4) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnumbytes_279
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vtotal_num_284
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="wptr"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="payload"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_3.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_3.getElse().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-41"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_18.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vp_276, Variable vnumbytes_279, RelationalOperation target_11, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="wptr"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_4.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="buf"
		and target_4.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_4.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="readidx"
		and target_4.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnumbytes_279
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_5(Variable vp_276, Variable vnumbytes_279, RelationalOperation target_11, ExprStmt target_5) {
		target_5.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="readidx"
		and target_5.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_5.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vnumbytes_279
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_6(Variable vp_276, Variable vnumbytes_279, RelationalOperation target_11, ExprStmt target_6) {
		target_6.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="wptr"
		and target_6.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vnumbytes_279
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_7(Variable vp_276, Variable vnumbytes_279, RelationalOperation target_11, ExprStmt target_7) {
		target_7.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data_num"
		and target_7.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_7.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vnumbytes_279
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_8(Variable vp_276, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getLesserOperand().(PointerFieldAccess).getTarget().getName()="packet_length"
		and target_8.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_8.getGreaterOperand().(Literal).getValue()="1"
}

predicate func_9(Variable vp_276, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="packet_length"
		and target_9.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_9.getLesserOperand().(Literal).getValue()="40000"
}

predicate func_10(Variable vp_276, Variable vtotal_num_284, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtotal_num_284
		and target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="packet_length"
		and target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="mac_len"
		and target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mac"
		and target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="remote"
		and target_10.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_11(Variable vnumbytes_279, RelationalOperation target_11) {
		 (target_11 instanceof GTExpr or target_11 instanceof LTExpr)
		and target_11.getGreaterOperand().(VariableAccess).getTarget()=vnumbytes_279
		and target_11.getLesserOperand().(Literal).getValue()="0"
}

predicate func_12(Variable vblocksize_282, RelationalOperation target_12) {
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getGreaterOperand().(VariableAccess).getTarget()=vblocksize_282
		and target_12.getLesserOperand().(Literal).getValue()="5"
}

predicate func_13(Variable vp_276, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="wptr"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="payload"
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
}

predicate func_14(Variable vp_276, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data_num"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="wptr"
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="payload"
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
}

predicate func_15(Variable vp_276, Variable vblock_281, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="padding_length"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_15.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vblock_281
		and target_15.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="4"
}

predicate func_16(Variable vnumbytes_279, Variable vblocksize_282, ExprStmt target_16) {
		target_16.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vnumbytes_279
		and target_16.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vblocksize_282
}

predicate func_17(Variable vp_276, Variable vtotal_num_284, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="total_num"
		and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
		and target_17.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtotal_num_284
}

predicate func_18(Variable vp_276, ExprStmt target_18) {
		target_18.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data_num"
		and target_18.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_276
}

from Function func, Variable vp_276, Variable vnumbytes_279, Variable vblock_281, Variable vblocksize_282, Variable vtotal_num_284, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, RelationalOperation target_8, RelationalOperation target_9, ExprStmt target_10, RelationalOperation target_11, RelationalOperation target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18
where
not func_0(vp_276, target_8, target_9, target_10)
and not func_2(vp_276, vblock_281, vblocksize_282, vtotal_num_284, target_12, target_13, target_14, target_15, target_16, target_17)
and not func_3(vp_276, vnumbytes_279, vtotal_num_284, target_11, target_18, target_4)
and func_4(vp_276, vnumbytes_279, target_11, target_4)
and func_5(vp_276, vnumbytes_279, target_11, target_5)
and func_6(vp_276, vnumbytes_279, target_11, target_6)
and func_7(vp_276, vnumbytes_279, target_11, target_7)
and func_8(vp_276, target_8)
and func_9(vp_276, target_9)
and func_10(vp_276, vtotal_num_284, target_10)
and func_11(vnumbytes_279, target_11)
and func_12(vblocksize_282, target_12)
and func_13(vp_276, target_13)
and func_14(vp_276, target_14)
and func_15(vp_276, vblock_281, target_15)
and func_16(vnumbytes_279, vblocksize_282, target_16)
and func_17(vp_276, vtotal_num_284, target_17)
and func_18(vp_276, target_18)
and vp_276.getType().hasName("transportpacket *")
and vnumbytes_279.getType().hasName("int")
and vblock_281.getType().hasName("unsigned char[32]")
and vblocksize_282.getType().hasName("int")
and vtotal_num_284.getType().hasName("size_t")
and vp_276.getParentScope+() = func
and vnumbytes_279.getParentScope+() = func
and vblock_281.getParentScope+() = func
and vblocksize_282.getParentScope+() = func
and vtotal_num_284.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
