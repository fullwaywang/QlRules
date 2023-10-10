/**
 * @name ffmpeg-7d49f79f1cd47783a963a757a6563b9cac29db62-qdm2_decode_frame
 * @id cpp/ffmpeg/7d49f79f1cd47783a963a757a6563b9cac29db62/qdm2-decode-frame
 * @description ffmpeg-7d49f79f1cd47783a963a757a6563b9cac29db62-libavcodec/qdm2.c-qdm2_decode_frame CVE-2011-4351
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vavctx_1955, Variable vs_1961, ExprStmt target_8, ExprStmt target_9, ReturnStmt target_10, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="16"
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1961
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="frame_size"
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1961
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(FunctionCall).getTarget().hasName("av_get_bytes_per_sample")
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sample_fmt"
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_1955
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1)
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vavctx_1955, Variable vs_1961, ExprStmt target_8, ExprStmt target_9, ReturnStmt target_10) {
	exists(MulExpr target_3 |
		target_3.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="16"
		and target_3.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_3.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1961
		and target_3.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="frame_size"
		and target_3.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1961
		and target_3.getRightOperand().(FunctionCall).getTarget().hasName("av_get_bytes_per_sample")
		and target_3.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sample_fmt"
		and target_3.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_1955
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_4(Parameter vavctx_1955, Parameter vdata_size_1956, ExprStmt target_8, PointerDereferenceExpr target_11, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdata_size_1956
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_1955
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Output buffer is too small\n"
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_4)
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_11.getOperand().(VariableAccess).getLocation()))
}

predicate func_5(Function func) {
	exists(AssignExpr target_5 |
		target_5.getLValue() instanceof PointerDereferenceExpr
		and target_5.getRValue().(VariableAccess).getType().hasName("int")
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vdata_size_1956, PointerDereferenceExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vdata_size_1956
		and target_6.getParent().(AssignExpr).getLValue() = target_6
		and target_6.getParent().(AssignExpr).getRValue() instanceof PointerArithmeticOperation
}

predicate func_7(Parameter vdata_1956, Variable vout_1962, PointerArithmeticOperation target_7) {
		target_7.getLeftOperand().(VariableAccess).getTarget()=vout_1962
		and target_7.getRightOperand().(VariableAccess).getTarget()=vdata_1956
		and target_7.getParent().(AssignExpr).getRValue() = target_7
		and target_7.getParent().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
}

predicate func_8(Parameter vavctx_1955, Parameter vdata_1956, Parameter vdata_size_1956, Variable vs_1961, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_1955
		and target_8.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="48"
		and target_8.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="decode(%d): %p[%d] -> %p[%d]\n"
		and target_8.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("const uint8_t *")
		and target_8.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="checksum_size"
		and target_8.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1961
		and target_8.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vdata_1956
		and target_8.getExpr().(FunctionCall).getArgument(7).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdata_size_1956
}

predicate func_9(Variable vs_1961, Variable vout_1962, ExprStmt target_9) {
		target_9.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vout_1962
		and target_9.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_9.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1961
		and target_9.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="frame_size"
		and target_9.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1961
}

predicate func_10(Variable vs_1961, ReturnStmt target_10) {
		target_10.getExpr().(PointerFieldAccess).getTarget().getName()="checksum_size"
		and target_10.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1961
}

predicate func_11(Parameter vdata_size_1956, PointerDereferenceExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=vdata_size_1956
}

from Function func, Parameter vavctx_1955, Parameter vdata_1956, Parameter vdata_size_1956, Variable vs_1961, Variable vout_1962, PointerDereferenceExpr target_6, PointerArithmeticOperation target_7, ExprStmt target_8, ExprStmt target_9, ReturnStmt target_10, PointerDereferenceExpr target_11
where
not func_1(vavctx_1955, vs_1961, target_8, target_9, target_10, func)
and not func_4(vavctx_1955, vdata_size_1956, target_8, target_11, func)
and not func_5(func)
and func_6(vdata_size_1956, target_6)
and func_7(vdata_1956, vout_1962, target_7)
and func_8(vavctx_1955, vdata_1956, vdata_size_1956, vs_1961, target_8)
and func_9(vs_1961, vout_1962, target_9)
and func_10(vs_1961, target_10)
and func_11(vdata_size_1956, target_11)
and vavctx_1955.getType().hasName("AVCodecContext *")
and vdata_1956.getType().hasName("void *")
and vdata_size_1956.getType().hasName("int *")
and vs_1961.getType().hasName("QDM2Context *")
and vout_1962.getType().hasName("int16_t *")
and vavctx_1955.getFunction() = func
and vdata_1956.getFunction() = func
and vdata_size_1956.getFunction() = func
and vs_1961.(LocalVariable).getFunction() = func
and vout_1962.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
