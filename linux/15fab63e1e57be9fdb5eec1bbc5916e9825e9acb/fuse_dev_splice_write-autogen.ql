/**
 * @name linux-15fab63e1e57be9fdb5eec1bbc5916e9825e9acb-fuse_dev_splice_write
 * @id cpp/linux/15fab63e1e57be9fdb5eec1bbc5916e9825e9acb/fuse-dev-splice-write
 * @description linux-15fab63e1e57be9fdb5eec1bbc5916e9825e9acb-fuse_dev_splice_write 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrem_2015, Variable vibuf_2044, Parameter vpipe_2006) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("pipe_buf_get")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpipe_2006
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vibuf_2044
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vrem_2015
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vibuf_2044)
}

predicate func_1(Parameter vlen_2008, Variable vrem_2015, Parameter vpipe_2006) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("pipe_unlock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpipe_2006
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrem_2015
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_2008)
}

predicate func_2(Variable vrem_2015, Variable vibuf_2044, Variable vobuf_2045) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobuf_2045
		and target_2.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vibuf_2044
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vrem_2015
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vibuf_2044)
}

predicate func_3(Variable vrem_2015, Variable vibuf_2044, Variable vobuf_2045) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_3.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobuf_2045
		and target_3.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="4294967291"
		and target_3.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(Literal).getValue()="4"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vrem_2015
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vibuf_2044)
}

predicate func_4(Variable vrem_2015, Variable vibuf_2044, Variable vobuf_2045) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="len"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobuf_2045
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vrem_2015
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vrem_2015
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vibuf_2044)
}

predicate func_5(Variable vrem_2015, Variable vibuf_2044, Variable vobuf_2045) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="offset"
		and target_5.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vibuf_2044
		and target_5.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="len"
		and target_5.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobuf_2045
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vrem_2015
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vibuf_2044)
}

predicate func_6(Variable vrem_2015, Variable vibuf_2044, Variable vobuf_2045) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="len"
		and target_6.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vibuf_2044
		and target_6.getExpr().(AssignSubExpr).getRValue().(PointerFieldAccess).getTarget().getName()="len"
		and target_6.getExpr().(AssignSubExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobuf_2045
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vrem_2015
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vibuf_2044)
}

predicate func_9(Parameter vlen_2008, Variable vrem_2015) {
	exists(GotoStmt target_9 |
		target_9.toString() = "goto ..."
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrem_2015
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_2008)
}

predicate func_10(Variable vrem_2015, Variable vibuf_2044, Parameter vpipe_2006) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(FunctionCall).getTarget().hasName("pipe_buf_get")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpipe_2006
		and target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vibuf_2044
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vrem_2015
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vibuf_2044)
}

from Function func, Parameter vlen_2008, Variable vrem_2015, Variable vibuf_2044, Variable vobuf_2045, Parameter vpipe_2006
where
not func_0(vrem_2015, vibuf_2044, vpipe_2006)
and func_1(vlen_2008, vrem_2015, vpipe_2006)
and func_2(vrem_2015, vibuf_2044, vobuf_2045)
and func_3(vrem_2015, vibuf_2044, vobuf_2045)
and func_4(vrem_2015, vibuf_2044, vobuf_2045)
and func_5(vrem_2015, vibuf_2044, vobuf_2045)
and func_6(vrem_2015, vibuf_2044, vobuf_2045)
and func_9(vlen_2008, vrem_2015)
and func_10(vrem_2015, vibuf_2044, vpipe_2006)
and vlen_2008.getType().hasName("size_t")
and vrem_2015.getType().hasName("size_t")
and vibuf_2044.getType().hasName("pipe_buffer *")
and vobuf_2045.getType().hasName("pipe_buffer *")
and vpipe_2006.getType().hasName("pipe_inode_info *")
and vlen_2008.getParentScope+() = func
and vrem_2015.getParentScope+() = func
and vibuf_2044.getParentScope+() = func
and vobuf_2045.getParentScope+() = func
and vpipe_2006.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
