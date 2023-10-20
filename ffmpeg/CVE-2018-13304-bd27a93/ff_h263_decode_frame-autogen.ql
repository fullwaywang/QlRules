/**
 * @name ffmpeg-bd27a9364ca274ca97f1df6d984e88a0700fb235-ff_h263_decode_frame
 * @id cpp/ffmpeg/bd27a9364ca274ca97f1df6d984e88a0700fb235/ff-h263-decode-frame
 * @description ffmpeg-bd27a9364ca274ca97f1df6d984e88a0700fb235-libavcodec/h263dec.c-ff_h263_decode_frame CVE-2018-13304
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_426, ExprStmt target_2, AddressOfExpr target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="studio_profile"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_426
		and target_0.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(42)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(42).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_426, Function func, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("ff_er_frame_end")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="er"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_426
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vs_426, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="error_status_table"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="er"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_426
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="mb_num"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_426
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getValue()="14"
}

predicate func_3(Variable vs_426, AddressOfExpr target_3) {
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="er"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_426
}

from Function func, Variable vs_426, ExprStmt target_1, ExprStmt target_2, AddressOfExpr target_3
where
not func_0(vs_426, target_2, target_3, func)
and func_1(vs_426, func, target_1)
and func_2(vs_426, target_2)
and func_3(vs_426, target_3)
and vs_426.getType().hasName("MpegEncContext *")
and vs_426.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
