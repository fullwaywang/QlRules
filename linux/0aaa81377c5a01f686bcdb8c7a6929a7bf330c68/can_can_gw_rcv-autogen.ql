/**
 * @name linux-0aaa81377c5a01f686bcdb8c7a6929a7bf330c68-can_can_gw_rcv
 * @id cpp/linux/0aaa81377c5a01f686bcdb8c7a6929a7bf330c68/can_can_gw_rcv
 * @description linux-0aaa81377c5a01f686bcdb8c7a6929a7bf330c68-can_can_gw_rcv CVE-2019-3701
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vnskb_352, Variable vmodidx_353) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnskb_352
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(0).(TypeName).getType() instanceof Struct
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getTarget().getName()="data"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getRightOperand().(BuiltInOperationBuiltInOffsetOf).getChild(1).(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vmodidx_353)
}

predicate func_3(Variable vcf_351) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="can_dlc"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcf_351
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
		and target_3.getThen().(GotoStmt).toString() = "goto ..."
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof ValueFieldAccess)
}

predicate func_4(Variable vcf_351, Variable vmodidx_353) {
	exists(IfStmt target_4 |
		target_4.getCondition() instanceof ValueFieldAccess
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="can_dlc"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcf_351
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_4.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vmodidx_353)
}

predicate func_6(Function func) {
	exists(LabelStmt target_6 |
		target_6.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_6))
}

predicate func_7(Variable vgwj_350, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="deleted_frames"
		and target_7.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_7))
}

predicate func_8(Variable vnskb_352, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("kfree_skb")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnskb_352
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_8))
}

predicate func_9(Function func) {
	exists(ReturnStmt target_9 |
		target_9.toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_9))
}

predicate func_11(Variable vgwj_350, Variable vcf_351) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="crc8"
		and target_11.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="csumfunc"
		and target_11.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mod"
		and target_11.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350
		and target_11.getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vcf_351
		and target_11.getExpr().(ExprCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="crc8"
		and target_11.getExpr().(ExprCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="csum"
		and target_11.getExpr().(ExprCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mod"
		and target_11.getExpr().(ExprCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350
		and target_11.getParent().(IfStmt).getCondition().(ValueFieldAccess).getTarget().getName()="crc8"
		and target_11.getParent().(IfStmt).getCondition().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="csumfunc"
		and target_11.getParent().(IfStmt).getCondition().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mod"
		and target_11.getParent().(IfStmt).getCondition().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350)
}

predicate func_13(Variable vgwj_350, Variable vcf_351) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="xor"
		and target_13.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="csumfunc"
		and target_13.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mod"
		and target_13.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350
		and target_13.getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vcf_351
		and target_13.getExpr().(ExprCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="xor"
		and target_13.getExpr().(ExprCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="csum"
		and target_13.getExpr().(ExprCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mod"
		and target_13.getExpr().(ExprCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350
		and target_13.getParent().(IfStmt).getCondition().(ValueFieldAccess).getTarget().getName()="xor"
		and target_13.getParent().(IfStmt).getCondition().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="csumfunc"
		and target_13.getParent().(IfStmt).getCondition().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mod"
		and target_13.getParent().(IfStmt).getCondition().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350)
}

predicate func_14(Variable vgwj_350) {
	exists(PointerFieldAccess target_14 |
		target_14.getTarget().getName()="handled_frames"
		and target_14.getQualifier().(VariableAccess).getTarget()=vgwj_350)
}

predicate func_15(Variable vgwj_350, Variable vcf_351, Variable vmodidx_353) {
	exists(ExprCall target_15 |
		target_15.getExpr().(PointerDereferenceExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="modfunc"
		and target_15.getExpr().(PointerDereferenceExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mod"
		and target_15.getExpr().(PointerDereferenceExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350
		and target_15.getExpr().(PointerDereferenceExpr).getOperand().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vmodidx_353
		and target_15.getArgument(0).(VariableAccess).getTarget()=vcf_351
		and target_15.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mod"
		and target_15.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350)
}

predicate func_16(Variable vgwj_350, Variable vcf_351) {
	exists(ExprCall target_16 |
		target_16.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="crc8"
		and target_16.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="csumfunc"
		and target_16.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mod"
		and target_16.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350
		and target_16.getArgument(0).(VariableAccess).getTarget()=vcf_351
		and target_16.getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="crc8"
		and target_16.getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="csum"
		and target_16.getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mod"
		and target_16.getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350)
}

predicate func_17(Variable vgwj_350, Variable vcf_351) {
	exists(ExprCall target_17 |
		target_17.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="xor"
		and target_17.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="csumfunc"
		and target_17.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mod"
		and target_17.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350
		and target_17.getArgument(0).(VariableAccess).getTarget()=vcf_351
		and target_17.getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="xor"
		and target_17.getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="csum"
		and target_17.getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mod"
		and target_17.getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350)
}

predicate func_18(Variable vnskb_352) {
	exists(PointerFieldAccess target_18 |
		target_18.getTarget().getName()="data"
		and target_18.getQualifier().(VariableAccess).getTarget()=vnskb_352)
}

predicate func_19(Variable vgwj_350, Variable vnskb_352) {
	exists(FunctionCall target_19 |
		target_19.getTarget().hasName("can_send")
		and target_19.getArgument(0).(VariableAccess).getTarget()=vnskb_352
		and target_19.getArgument(1).(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_19.getArgument(1).(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgwj_350
		and target_19.getArgument(1).(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1")
}

from Function func, Variable vgwj_350, Variable vcf_351, Variable vnskb_352, Variable vmodidx_353
where
not func_0(vnskb_352, vmodidx_353)
and not func_3(vcf_351)
and not func_4(vcf_351, vmodidx_353)
and not func_6(func)
and not func_7(vgwj_350, func)
and not func_8(vnskb_352, func)
and not func_9(func)
and func_11(vgwj_350, vcf_351)
and func_13(vgwj_350, vcf_351)
and vgwj_350.getType().hasName("cgw_job *")
and func_14(vgwj_350)
and vcf_351.getType().hasName("can_frame *")
and func_15(vgwj_350, vcf_351, vmodidx_353)
and func_16(vgwj_350, vcf_351)
and func_17(vgwj_350, vcf_351)
and vnskb_352.getType().hasName("sk_buff *")
and func_18(vnskb_352)
and func_19(vgwj_350, vnskb_352)
and vmodidx_353.getType().hasName("int")
and vgwj_350.getParentScope+() = func
and vcf_351.getParentScope+() = func
and vnskb_352.getParentScope+() = func
and vmodidx_353.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
