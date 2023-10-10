/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_read_plus_rsize
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-read-plus-rsize
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_read_plus_rsize 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_4(Parameter vrqstp_2870) {
	exists(VariableDeclarationEntry target_4 |
		target_4.getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getTarget().hasName("svc_max_payload")
		and target_4.getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrqstp_2870)
}

predicate func_7(Parameter vop_2870) {
	exists(VariableDeclarationEntry target_7 |
		target_7.getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getTarget().getName()="rd_length"
		and target_7.getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="read"
		and target_7.getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_7.getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_2870)
}

predicate func_12(Parameter vrqstp_2870) {
	exists(FunctionCall target_12 |
		target_12.getTarget().hasName("nfsd4_max_payload")
		and target_12.getArgument(0).(VariableAccess).getTarget()=vrqstp_2870)
}

predicate func_17(Parameter vop_2870) {
	exists(VariableAccess target_17 |
		target_17.getTarget()=vop_2870)
}

predicate func_18(Variable vmaxcount_2872) {
	exists(VariableAccess target_18 |
		target_18.getTarget()=vmaxcount_2872)
}

predicate func_24(Variable vmaxcount_2872) {
	exists(DeclStmt target_24 |
		target_24.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vmaxcount_2872)
}

predicate func_26(Parameter vop_2870) {
	exists(PointerFieldAccess target_26 |
		target_26.getTarget().getName()="u"
		and target_26.getQualifier().(VariableAccess).getTarget()=vop_2870)
}

from Function func, Parameter vrqstp_2870, Parameter vop_2870, Variable vmaxcount_2872, Variable v__UNIQUE_ID___x2494_2873, Variable v__UNIQUE_ID___y2495_2873
where
func_4(vrqstp_2870)
and func_7(vop_2870)
and not func_12(vrqstp_2870)
and func_17(vop_2870)
and func_18(vmaxcount_2872)
and func_24(vmaxcount_2872)
and vrqstp_2870.getType().hasName("svc_rqst *")
and vop_2870.getType().hasName("nfsd4_op *")
and func_26(vop_2870)
and v__UNIQUE_ID___y2495_2873.getType().hasName("u32")
and vrqstp_2870.getParentScope+() = func
and vop_2870.getParentScope+() = func
and vmaxcount_2872.getParentScope+() = func
and v__UNIQUE_ID___x2494_2873.getParentScope+() = func
and v__UNIQUE_ID___y2495_2873.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
