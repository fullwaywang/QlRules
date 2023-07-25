/**
 * @name ffmpeg-9d00fb9d70ee8c0cc7002b89318c5be00f1bbdad-mxf_read_primer_pack
 * @id cpp/ffmpeg/9d00fb9d70ee8c0cc7002b89318c5be00f1bbdad/mxf-read-primer-pack
 * @description ffmpeg-9d00fb9d70ee8c0cc7002b89318c5be00f1bbdad-libavformat/mxfdec.c-mxf_read_primer_pack CVE-2017-14169
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vitem_num_496, BlockStmt target_2, RelationalOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vitem_num_496
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vitem_num_496, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vitem_num_496
		and target_1.getLesserOperand().(Literal).getValue()="65536"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vitem_num_496, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fc"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="item_num %d is too large\n"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vitem_num_496
}

from Function func, Variable vitem_num_496, RelationalOperation target_1, BlockStmt target_2
where
not func_0(vitem_num_496, target_2, target_1)
and func_1(vitem_num_496, target_2, target_1)
and func_2(vitem_num_496, target_2)
and vitem_num_496.getType().hasName("int")
and vitem_num_496.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
