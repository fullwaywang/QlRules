/**
 * @name ffmpeg-9929991da7b843e7d80154fcacc4e80579b86a2d-prepare_sdp_description
 * @id cpp/ffmpeg/9929991da7b843e7d80154fcacc4e80579b86a2d/prepare-sdp-description
 * @description ffmpeg-9929991da7b843e7d80154fcacc4e80579b86a2d-ffserver.c-prepare_sdp_description CVE-2012-6617
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("AVOutputFormat *")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vavc_2938, EqualityOperation target_2, AddressOfExpr target_3, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="oformat"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavc_2938
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("AVOutputFormat *")
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_1)
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vavc_2938, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vavc_2938
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
}

predicate func_3(Variable vavc_2938, AddressOfExpr target_3) {
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="metadata"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavc_2938
}

from Function func, Variable vavc_2938, EqualityOperation target_2, AddressOfExpr target_3
where
not func_0(func)
and not func_1(vavc_2938, target_2, target_3, func)
and func_2(vavc_2938, target_2)
and func_3(vavc_2938, target_3)
and vavc_2938.getType().hasName("AVFormatContext *")
and vavc_2938.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
