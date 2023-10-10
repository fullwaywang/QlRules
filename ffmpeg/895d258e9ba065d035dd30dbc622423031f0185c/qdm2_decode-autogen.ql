/**
 * @name ffmpeg-895d258e9ba065d035dd30dbc622423031f0185c-qdm2_decode
 * @id cpp/ffmpeg/895d258e9ba065d035dd30dbc622423031f0185c/qdm2-decode
 * @description ffmpeg-895d258e9ba065d035dd30dbc622423031f0185c-libavcodec/qdm2.c-qdm2_decode CVE-2011-4351
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vframe_size_1897, AddressOfExpr target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vframe_size_1897
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="1024"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vframe_size_1897, AddressOfExpr target_1) {
		target_1.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="output_buffer"
		and target_1.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("QDM2Context *")
		and target_1.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vframe_size_1897
}

from Function func, Variable vframe_size_1897, AddressOfExpr target_1
where
not func_0(vframe_size_1897, target_1, func)
and func_1(vframe_size_1897, target_1)
and vframe_size_1897.getType().hasName("const int")
and vframe_size_1897.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
