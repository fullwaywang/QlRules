/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-xdr_buf_subsegment
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/xdr-buf-subsegment
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-xdr_buf_subsegment 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vlen_1581) {
	exists(VariableDeclarationEntry target_1 |
		target_1.getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vlen_1581)
}

predicate func_3(Parameter vbase_1581, Parameter vbuf_1580) {
	exists(VariableDeclarationEntry target_3 |
		target_3.getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="iov_len"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="head"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_1580
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vbase_1581)
}

predicate func_9(Parameter vbase_1581, Parameter vbuf_1580) {
	exists(VariableDeclarationEntry target_9 |
		target_9.getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="page_len"
		and target_9.getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_1580
		and target_9.getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vbase_1581)
}

predicate func_11(Parameter vlen_1581) {
	exists(VariableDeclarationEntry target_11 |
		target_11.getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vlen_1581)
}

predicate func_17(Parameter vlen_1581) {
	exists(VariableDeclarationEntry target_17 |
		target_17.getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vlen_1581)
}

predicate func_19(Parameter vbase_1581, Parameter vbuf_1580) {
	exists(VariableDeclarationEntry target_19 |
		target_19.getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="iov_len"
		and target_19.getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tail"
		and target_19.getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_1580
		and target_19.getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_19.getVariable().getInitializer().(Initializer).getExpr().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vbase_1581)
}

from Function func, Parameter vbase_1581, Parameter vlen_1581, Parameter vbuf_1580, Variable v__UNIQUE_ID___x2978_1586, Variable v__UNIQUE_ID___y2979_1586, Variable v__UNIQUE_ID___x2980_1597, Variable v__UNIQUE_ID___y2981_1597, Variable v__UNIQUE_ID___x2982_1612, Variable v__UNIQUE_ID___y2983_1612
where
func_1(vlen_1581)
and func_3(vbase_1581, vbuf_1580)
and func_9(vbase_1581, vbuf_1580)
and func_11(vlen_1581)
and func_17(vlen_1581)
and func_19(vbase_1581, vbuf_1580)
and vbase_1581.getType().hasName("unsigned int")
and vlen_1581.getType().hasName("unsigned int")
and vbuf_1580.getType().hasName("const xdr_buf *")
and vbase_1581.getParentScope+() = func
and vlen_1581.getParentScope+() = func
and vbuf_1580.getParentScope+() = func
and v__UNIQUE_ID___x2978_1586.getParentScope+() = func
and v__UNIQUE_ID___y2979_1586.getParentScope+() = func
and v__UNIQUE_ID___x2980_1597.getParentScope+() = func
and v__UNIQUE_ID___y2981_1597.getParentScope+() = func
and v__UNIQUE_ID___x2982_1612.getParentScope+() = func
and v__UNIQUE_ID___y2983_1612.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
