export function LoadingSpinner() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="w-5 h-5 border-2 border-[#3e3e42] border-t-[#007acc] rounded-full animate-spin" />
    </div>
  );
}
