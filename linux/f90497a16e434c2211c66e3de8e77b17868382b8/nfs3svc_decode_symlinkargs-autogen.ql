/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfs3svc_decode_symlinkargs
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfs3svc-decode-symlinkargs
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfs3svc_decode_symlinkargs 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vxdr_615) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xdr_inline_decode")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vxdr_615
		and target_0.getArgument(1) instanceof PointerFieldAccess)
}

predicate func_1(Variable vargs_617) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(ValueFieldAccess).getTarget().getName()="iov_base"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="first"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vargs_617
		and target_1.getAnOperand().(Literal).getValue()="0")
}

predicate func_2(Variable vhead_618) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="iov_len"
		and target_2.getQualifier().(VariableAccess).getTarget()=vhead_618)
}

predicate func_3(Parameter vxdr_615) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("xdr_stream_pos")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vxdr_615)
}

predicate func_4(Variable vargs_617) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="tlen"
		and target_4.getQualifier().(VariableAccess).getTarget()=vargs_617
		and target_4.getParent().(FunctionCall).getParent().(LTExpr).getGreaterOperand() instanceof FunctionCall)
}

predicate func_6(Parameter vrqstp_615, Function func) {
	exists(DeclStmt target_6 |
		target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getTarget().getName()="tail"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rq_arg"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrqstp_615
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_7(Function func) {
	exists(DeclStmt target_7 |
		target_7.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof Size_t
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_8(Parameter vrqstp_615, Variable vtail_619, Variable vremaining_620) {
	exists(AssignExpr target_8 |
		target_8.getLValue().(VariableAccess).getTarget()=vremaining_620
		and target_8.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand() instanceof PointerFieldAccess
		and target_8.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="page_len"
		and target_8.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rq_arg"
		and target_8.getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrqstp_615
		and target_8.getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="iov_len"
		and target_8.getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtail_619)
}

predicate func_9(Variable vremaining_620, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vremaining_620
		and target_9.getExpr().(AssignSubExpr).getRValue() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

predicate func_10(Variable vremaining_620, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vremaining_620
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("xdr_align_size")
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0) instanceof PointerFieldAccess
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

predicate func_11(Parameter vxdr_615, Variable vargs_617, Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="iov_base"
		and target_11.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="first"
		and target_11.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vargs_617
		and target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="p"
		and target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vxdr_615
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11)
}

predicate func_14(Variable vargs_617) {
	exists(PointerFieldAccess target_14 |
		target_14.getTarget().getName()="first"
		and target_14.getQualifier().(VariableAccess).getTarget()=vargs_617)
}

from Function func, Parameter vrqstp_615, Parameter vxdr_615, Variable vargs_617, Variable vhead_618, Variable vtail_619, Variable vremaining_620
where
not func_0(vxdr_615)
and not func_1(vargs_617)
and func_2(vhead_618)
and func_3(vxdr_615)
and func_4(vargs_617)
and func_6(vrqstp_615, func)
and func_7(func)
and func_8(vrqstp_615, vtail_619, vremaining_620)
and func_9(vremaining_620, func)
and func_10(vremaining_620, func)
and func_11(vxdr_615, vargs_617, func)
and vrqstp_615.getType().hasName("svc_rqst *")
and vxdr_615.getType().hasName("xdr_stream *")
and vargs_617.getType().hasName("nfsd3_symlinkargs *")
and func_14(vargs_617)
and vhead_618.getType().hasName("kvec *")
and vtail_619.getType().hasName("kvec *")
and vremaining_620.getType().hasName("size_t")
and vrqstp_615.getParentScope+() = func
and vxdr_615.getParentScope+() = func
and vargs_617.getParentScope+() = func
and vhead_618.getParentScope+() = func
and vtail_619.getParentScope+() = func
and vremaining_620.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
