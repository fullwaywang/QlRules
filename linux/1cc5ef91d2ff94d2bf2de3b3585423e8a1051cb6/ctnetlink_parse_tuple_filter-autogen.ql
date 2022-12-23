/**
 * @name linux-1cc5ef91d2ff94d2bf2de3b3585423e8a1051cb6-ctnetlink_parse_tuple_filter
 * @id cpp/linux/1cc5ef91d2ff94d2bf2de3b3585423e8a1051cb6/ctnetlink_parse_tuple_filter
 * @description linux-1cc5ef91d2ff94d2bf2de3b3585423e8a1051cb6-ctnetlink_parse_tuple_filter 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vl3num_1394, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vl3num_1394
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vl3num_1394
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-95"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="95"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

from Function func, Parameter vl3num_1394
where
not func_0(vl3num_1394, func)
and vl3num_1394.getType().hasName("u_int8_t")
and vl3num_1394.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
