/**
 * @name ffmpeg-912ce9dd2080c5837285a471d750fa311e09b555-ff_jpeg2000_cleanup
 * @id cpp/ffmpeg/912ce9dd2080c5837285a471d750fa311e09b555/ff-jpeg2000-cleanup
 * @description ffmpeg-912ce9dd2080c5837285a471d750fa311e09b555-libavcodec/jpeg2000.c-ff_jpeg2000_cleanup CVE-2013-7017
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vband_510, PointerArithmeticOperation target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="prec"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_510
		and target_0.getThen() instanceof BlockStmt
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vprec_512, BlockStmt target_1) {
		target_1.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_freep")
		and target_1.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="zerobits"
		and target_1.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprec_512
		and target_1.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_freep")
		and target_1.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cblkincl"
		and target_1.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprec_512
		and target_1.getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_freep")
		and target_1.getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cblk"
		and target_1.getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprec_512
}

predicate func_2(Variable vband_510, PointerArithmeticOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="prec"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_510
		and target_2.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vband_510, Variable vprec_512, BlockStmt target_1, PointerArithmeticOperation target_2
where
not func_0(vband_510, target_2)
and func_1(vprec_512, target_1)
and func_2(vband_510, target_2)
and vband_510.getType().hasName("Jpeg2000Band *")
and vprec_512.getType().hasName("Jpeg2000Prec *")
and vband_510.(LocalVariable).getFunction() = func
and vprec_512.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
