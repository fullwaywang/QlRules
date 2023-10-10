/**
 * @name ffmpeg-1d479300cbe0522c233b7d51148aea2b29bd29ad-nut_write_trailer
 * @id cpp/ffmpeg/1d479300cbe0522c233b7d51148aea2b29bd29ad/nut-write-trailer
 * @description ffmpeg-1d479300cbe0522c233b7d51148aea2b29bd29ad-libavformat/nutenc.c-nut_write_trailer CVE-2020-22044
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnut_1166, BlockStmt target_6, RelationalOperation target_7, ExprStmt target_8) {
	exists(NotExpr target_0 |
		target_0.getOperand().(PointerFieldAccess).getTarget().getName()="sp_count"
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnut_1166
		and target_0.getParent().(IfStmt).getThen()=target_6
		and target_7.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(LogicalAndExpr target_5, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getCondition()=target_5
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vnut_1166, Variable vbc_1167, Variable vdyn_bc_1167, LogicalAndExpr target_5, ExprStmt target_9, AddressOfExpr target_10, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof RelationalOperation
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("write_index")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnut_1166
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdyn_bc_1167
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("put_packet")
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnut_1166
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbc_1167
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdyn_bc_1167
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getValue()="5645505568151168590"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_2)
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_10.getOperand().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vnut_1166, Variable vret_1168, BlockStmt target_6, RelationalOperation target_3) {
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vret_1168
		and target_3.getLesserOperand().(Literal).getValue()="0"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="sp_count"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnut_1166
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_6
}

*/
/*predicate func_4(Variable vnut_1166, Variable vret_1168, BlockStmt target_6, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="sp_count"
		and target_4.getQualifier().(VariableAccess).getTarget()=vnut_1166
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vret_1168
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_6
}

*/
predicate func_5(Variable vnut_1166, BlockStmt target_6, LogicalAndExpr target_5) {
		target_5.getAnOperand() instanceof RelationalOperation
		and target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="sp_count"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnut_1166
		and target_5.getParent().(IfStmt).getThen()=target_6
}

predicate func_6(Variable vnut_1166, Variable vbc_1167, Variable vdyn_bc_1167, BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="0"
		and target_6.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("write_index")
		and target_6.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnut_1166
		and target_6.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdyn_bc_1167
		and target_6.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("put_packet")
		and target_6.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnut_1166
		and target_6.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbc_1167
		and target_6.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdyn_bc_1167
		and target_6.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_6.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getValue()="5645505568151168590"
}

predicate func_7(Variable vnut_1166, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(PointerFieldAccess).getTarget().getName()="header_count"
		and target_7.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnut_1166
		and target_7.getGreaterOperand().(Literal).getValue()="3"
}

predicate func_8(Variable vnut_1166, Variable vdyn_bc_1167, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("write_index")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnut_1166
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdyn_bc_1167
}

predicate func_9(Variable vbc_1167, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("write_headers")
		and target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbc_1167
}

predicate func_10(Variable vdyn_bc_1167, AddressOfExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vdyn_bc_1167
}

from Function func, Variable vnut_1166, Variable vbc_1167, Variable vdyn_bc_1167, Variable vret_1168, LogicalAndExpr target_5, BlockStmt target_6, RelationalOperation target_7, ExprStmt target_8, ExprStmt target_9, AddressOfExpr target_10
where
not func_0(vnut_1166, target_6, target_7, target_8)
and not func_1(target_5, func)
and not func_2(vnut_1166, vbc_1167, vdyn_bc_1167, target_5, target_9, target_10, func)
and func_5(vnut_1166, target_6, target_5)
and func_6(vnut_1166, vbc_1167, vdyn_bc_1167, target_6)
and func_7(vnut_1166, target_7)
and func_8(vnut_1166, vdyn_bc_1167, target_8)
and func_9(vbc_1167, target_9)
and func_10(vdyn_bc_1167, target_10)
and vnut_1166.getType().hasName("NUTContext *")
and vbc_1167.getType().hasName("AVIOContext *")
and vdyn_bc_1167.getType().hasName("AVIOContext *")
and vret_1168.getType().hasName("int")
and vnut_1166.getParentScope+() = func
and vbc_1167.getParentScope+() = func
and vdyn_bc_1167.getParentScope+() = func
and vret_1168.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
