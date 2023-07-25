/**
 * @name ffmpeg-bd27a9364ca274ca97f1df6d984e88a0700fb235-ff_mpeg4_decode_picture_header
 * @id cpp/ffmpeg/bd27a9364ca274ca97f1df6d984e88a0700fb235/ff-mpeg4-decode-picture-header
 * @description ffmpeg-bd27a9364ca274ca97f1df6d984e88a0700fb235-libavcodec/mpeg4videodec.c-ff_mpeg4_decode_picture_header CVE-2018-13304
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(PointerFieldAccess target_4, Function func, DoStmt target_0) {
		target_0.getCondition() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="profile"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s->avctx->profile == 14"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("abort")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_0.getEnclosingFunction() = func
}

/*predicate func_1(Variable vs_3104, IfStmt target_1) {
		target_1.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="profile"
		and target_1.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_1.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_3104
		and target_1.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s->avctx->profile == 14"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("abort")
}

*/
/*predicate func_2(NotExpr target_5, Function func, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_2.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_2.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s->avctx->profile == 14"
		and target_2.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_2.getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_2.getEnclosingFunction() = func
}

*/
/*predicate func_3(NotExpr target_5, Function func, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("abort")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_3.getEnclosingFunction() = func
}

*/
predicate func_4(Variable vs_3104, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="studio_profile"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_3104
}

predicate func_5(NotExpr target_5) {
		target_5.getOperand() instanceof EqualityOperation
}

from Function func, Variable vs_3104, DoStmt target_0, PointerFieldAccess target_4, NotExpr target_5
where
func_0(target_4, func, target_0)
and func_4(vs_3104, target_4)
and func_5(target_5)
and vs_3104.getType().hasName("MpegEncContext *")
and vs_3104.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
