/**
 * @name flac-e1575e4a7c5157cbf4e4a16dbd39b74f7174c7be-write_bitbuffer_
 * @id cpp/flac/e1575e4a7c5157cbf4e4a16dbd39b74f7174c7be/write-bitbuffer-
 * @description flac-e1575e4a7c5157cbf4e4a16dbd39b74f7174c7be-src/libFLAC/stream_encoder.c-write_bitbuffer_ CVE-2021-0561
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vis_last_block_2594, Parameter vencoder_2594, BlockStmt target_2, EqualityOperation target_3, PointerFieldAccess target_4, PointerFieldAccess target_5) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vis_last_block_2594
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("FLAC__stream_encoder_get_verify_decoder_state")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vencoder_2594
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vencoder_2594, BlockStmt target_2, NotExpr target_1) {
		target_1.getOperand().(FunctionCall).getTarget().hasName("FLAC__stream_decoder_process_single")
		and target_1.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="decoder"
		and target_1.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="verify"
		and target_1.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="private_"
		and target_1.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vencoder_2594
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vencoder_2594, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("FLAC__bitwriter_release_buffer")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="frame"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="private_"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vencoder_2594
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("FLAC__bitwriter_clear")
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="frame"
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="private_"
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vencoder_2594
}

predicate func_3(Parameter vis_last_block_2594, Parameter vencoder_2594, EqualityOperation target_3) {
		target_3.getAnOperand().(FunctionCall).getTarget().hasName("write_frame_")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vencoder_2594
		and target_3.getAnOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vis_last_block_2594
}

predicate func_4(Parameter vencoder_2594, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="verify"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="private_"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vencoder_2594
}

predicate func_5(Parameter vencoder_2594, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="verify"
		and target_5.getQualifier().(PointerFieldAccess).getTarget().getName()="private_"
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vencoder_2594
}

from Function func, Parameter vis_last_block_2594, Parameter vencoder_2594, NotExpr target_1, BlockStmt target_2, EqualityOperation target_3, PointerFieldAccess target_4, PointerFieldAccess target_5
where
not func_0(vis_last_block_2594, vencoder_2594, target_2, target_3, target_4, target_5)
and func_1(vencoder_2594, target_2, target_1)
and func_2(vencoder_2594, target_2)
and func_3(vis_last_block_2594, vencoder_2594, target_3)
and func_4(vencoder_2594, target_4)
and func_5(vencoder_2594, target_5)
and vis_last_block_2594.getType().hasName("FLAC__bool")
and vencoder_2594.getType().hasName("FLAC__StreamEncoder *")
and vis_last_block_2594.getParentScope+() = func
and vencoder_2594.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
