/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_file_cache_stats_show
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd-file-cache-stats-show
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_file_cache_stats_show 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_3(Variable vht_1226) {
	exists(VariableDeclarationEntry target_3 |
		target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(FunctionDeclarationEntry).getType() instanceof VoidType
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="tbl"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vht_1226
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="1"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="tbl"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vht_1226
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="2"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="tbl"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vht_1226
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="4"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="tbl"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vht_1226
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="8"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="tbl"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vht_1226
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="8"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__compiletime_assert_2543")
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PointerDereferenceExpr).getOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tbl"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PointerDereferenceExpr).getOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vht_1226)
}

predicate func_4(Variable v__UNIQUE_ID_rcu2542_1233) {
	exists(VariableAccess target_4 |
		target_4.getTarget()=v__UNIQUE_ID_rcu2542_1233)
}

from Function func, Variable vht_1226, Variable v__UNIQUE_ID_rcu2542_1233
where
func_3(vht_1226)
and func_4(v__UNIQUE_ID_rcu2542_1233)
and vht_1226.getType().hasName("rhashtable *")
and vht_1226.getParentScope+() = func
and v__UNIQUE_ID_rcu2542_1233.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
